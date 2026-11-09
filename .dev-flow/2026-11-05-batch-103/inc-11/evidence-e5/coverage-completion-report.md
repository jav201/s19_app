# Inc 11 E5 coverage completion — independent static re-audit

## Scope and verdict

This report re-audits exactly the **136 requirement-case IDs** found by `E5-coverage-audit.md` (27 missing and 109 partial). The two application ATs are outside this table. No tests were run on Windows and no result cell was changed.

**Static totals: 98 full, 37 partial, 0 gap, 1 false-premise; total 136.** `full` means that the stated input and every expected observable are asserted through a product route. It does **not** mean runtime-verified. `partial` retains a concrete missing input, assertion, or required consumer route. `false-premise` means the original audit finding itself was wrong and the exact coverage already existed.

File aliases used below:

- **C** = `tests/test_b103_a2l_reader_coverage.py`
- **P** = `tests/test_b103_a2l_reader_perf.py`
- **R** = `tests/test_b103_a2l_reader.py`
- **E** = `tests/test_b103_a2l_reader_e5.py`
- **H** = `C::test_cov_read_48_hostile_corpus_equal_ref` (C:1534-1565), credited only where the corpus contains the required shape and its independent REF comparison asserts the missing observable.

## Original 27 missing cases

| ID | Node(s) | Verdict | Evidence / residual reason |
|---|---|---|---|
| R-A2L-READ.7/2 | C::test_cov_read_7_multiline_comment_glued_both_sides | full | H2b multiline glued comment and exact address asserted (C:302-318). |
| R-A2L-READ.13/4 | C::test_cov_read_13_multiline_string_end_closes_nothing; H | full | L7 BIT_MASK and one tag asserted (C:391-412); H compares section closure/end lines for the same corpus shape. |
| R-A2L-READ.54/2 | C::test_cov_read_54_compu_method_named_later_full | full | Real encoder returns exactly `(0, 5)` with no reason (C:1774-1778). |
| R-A2L-READ.54/4 | C::test_cov_read_54_compu_vtab_named_later | full | Later VT_K1/TAB_VERB resolution, entries, raw 1, physical `on`, and `ok` asserted (C:1796-1819). |
| R-A2L-READ.54/6 | C::test_cov_read_54_characteristic_display_format | full | `describe_definition` returns `%5.1` for CK1 (C:1840-1845). |
| R-A2L-READ.24/3 | C::test_cov_read_54_compu_method_long_id | full | CM_LID, `engine speed`, and LINEAR asserted (C:1822-1837). |
| R-A2L-READ.21/1 | C::test_cov_read_21_innermost_close_line | full | Exact input and MEASUREMENT `end_line == 23` asserted (C:1848-1855). |
| R-A2L-READ.65/4 | C::test_cov_read_65_hostile_corpus_mutations | partial | The 160×1,000 mutation/render loops exist (C:1568-1594), but the node has no assertion or executed-mutant oracle; execution alone is not credited. |
| R-A2L-READ.31/3 | C::test_cov_read_31_axis_descr_byte_order_not_tag | full | CURVE with AXIS_DESCR-local MSB_LAST retains module `big` (C:692-704). |
| R-A2L-READ.59/3 | C::test_cov_read_59_undeclared_layout_val_blk | full | Undeclared-layout VAL_BLK asserts `declares the sizes 4 and 5` (C:799-804). |
| R-A2L-READ.59/4 | C::test_cov_read_59_agreeing_pairs_no_error | full | All four agreeing pairs assert zero `declares the` errors (C:807-817). |
| R-A2L-READ.59/6 | C::test_cov_read_59_no_datatype_size_shapes | partial | Four shapes and duplicate errors now exist, but size diagnostics use substring `any`; required Line-20/begin-line text is not asserted for all four (C:820-836). |
| R-A2L-READ.59/7 | C::test_cov_read_59_synmap_length_span | full | Exact begin-line 2264/2266 diagnostic, no 2/2266 error, and agreeing length asserted (C:858-867). |
| R-A2L-READ.59/8 | C::test_cov_read_59_60_61_external_axis | full | COM_AXIS external pass asserts exact begin-line 2264/2266 diagnostic (C:894-901). |
| R-A2L-READ.68/2 | C::test_cov_read_68_inherited_byte_order_once | full | MOD_COMMON and layout sources each produce exactly one source-line diagnostic (C:1031-1056). |
| R-A2L-READ.33/1 | C::test_cov_read_33_six_tracked_display_identifiers | full | Six exact display identifiers and detail-card first lines without `/*` asserted (C:1064-1086). |
| R-A2L-READ.63/2 | C::test_cov_read_63_header_address_not_number | full | H2e exact Line-21 header-address diagnostic asserted (C:975-986). |
| R-A2L-READ.61/2 | C::test_cov_read_61_no_length_missing_invalid | full | Five missing/invalid size-keyword shapes all assert no length (C:1144-1155). |
| R-A2L-READ.61/4 | C::test_cov_read_61_definition_stays_refused | full | Two-LENGTH definition has no byte length and A2L-DEF-ADDRESS refusal (C:1171-1178). |
| R-A2L-READ.61/6 | C::test_cov_read_61_no_datatype_size_no_length | full | Four no-datatype-size shapes all assert no length (C:1181-1193). |
| R-A2L-READ.61/8 | C::test_cov_read_61_synmap_final_refusal | full | LENGTH 2264/x4 remain refused; 2266 survives (C:1196-1204). |
| R-A2L-READ.61/10 | C::test_cov_read_59_60_61_external_axis | full | External-axis MAP with LENGTH 2264 asserts final length None (C:894-901). |
| R-A2L-READ.48/2 | H | full | Corpus length 160; 157 REF comparisons plus two UTF-16 refusals and H3e control equal the documented 159 comparisons + control (C:1534-1565). |
| R-A2L-READ.50/2 | C::test_cov_read_50_summary_exact | full | Two-blank input collapses to one in rendered summary (C:1610-1613). |
| R-A2L-READ.50/3 | C::test_cov_read_50_summary_exact | full | Rendered summary retains `"one-line header"` with quotes (C:1602-1609). |
| R-A2L-READ.50/4 | C::test_cov_read_50_v161_characteristic_summary | full | V161 later-named CHARACTERISTIC summary prefix asserted (C:1616-1620). |
| R-A2L-076/3 | C::test_cov_read_076_mod_common_empty_meta | full | Empty-begin-words input asserts exact `- MOD_COMMON (lines ` prefix, proving no meta and one blank (C:1640-1649). |

## Original 109 partial cases

| ID | Node(s) | Verdict | Evidence / residual reason |
|---|---|---|---|
| R-A2L-READ.1/1 | C::test_cov_read_1_line_end_variants_equal_lf | full | CRLF compared with LF on complete tags, recursive sections/lines, and errors over tracked files (C:136-158). |
| R-A2L-READ.1/2 | C::test_cov_read_1_line_end_variants_equal_lf | full | Lone-CR arm has the same complete equality assertions (C:142-158). |
| R-A2L-READ.1/3 | C::test_cov_read_1_line_end_variants_equal_lf | full | Mixed arm cycles endings without fusing CR with an empty line's LF, then asserts complete equality (C:148-158). |
| R-A2L-READ.1/4 | C::test_cov_read_1_cr_cr_lf_full_equality | full | Complete tags/errors and recursive `2*k-1` section line mappings asserted (C:161-179). |
| R-A2L-READ.4/1 | C::test_cov_read_4_unexpected_character_exact | full | Eight characters each assert exactly one exact Line-20 error (C:182-193). |
| R-A2L-READ.4/2 | C::test_cov_read_4_comment_string_zero_errors | full | Comment/string input asserts zero errors (C:196-199). |
| R-A2L-READ.4/4 | C::test_cov_read_4_latin1_fffd_exact | full | Latin-1 comment/string/name shapes, one exact name-line error, and XL1 U+FFFD description asserted (C:202-218). |
| R-A2L-READ.4/5 | C::test_cov_read_4_after_address_length_matrix_exact | full | All 24 shapes assert exact line 20 for header address and 23 for LENGTH/MATRIX_DIM (C:221-240). |
| R-A2L-READ.4/6 | C::test_cov_read_4_quoted_name_esc_exact | full | Exactly one Line-20 U+001B error asserted (C:242-246). |
| R-A2L-READ.5/1 | C::test_cov_read_5_bom_before_version_equality | full | BOM/no-BOM sections, tags, and errors compared (C:249-257). |
| R-A2L-READ.5/2 | C::test_cov_read_5_bom_before_project_section | full | PROJECT section, zero errors, and address asserted (C:260-266). |
| R-A2L-READ.55/2 | R::test_r_a2l_read_55_binary_refused | partial | Refusal text is exact, but zero sections and zero tags are still not asserted (R:374-382). |
| R-A2L-READ.55/3 | R::test_r_a2l_read_55_nul_after_address_refused | partial | NUL-after-address refusal exists; zero sections/tags remain unasserted (R:385-389). |
| R-A2L-READ.55/4 | R::test_r_a2l_read_55_nul_in_comment_refused | partial | NUL-in-comment refusal exists; zero sections/tags remain unasserted (R:392-395). |
| R-A2L-READ.56/1 | C::test_cov_read_56_cap_and_views | partial | Length/marker and no early marker asserted, but the first 100 entries at 101 are not compared with the 100-error reading (C:1666-1675). |
| R-A2L-READ.56/2 | C::test_cov_read_56_cap_and_views | partial | Cap and final marker asserted, but only the first U+00E9 error is checked rather than all first 100 (C:1677-1682). |
| R-A2L-READ.56/3 | C::test_cov_read_56_cap_and_views | partial | Parser marker, rendered summary, and issue-model counts asserted (C:1684-1692); required real Workspace and Issues screens are not exercised. |
| R-A2L-READ.56/4 | C::test_cov_read_56_cap_and_views | full | Public list/cap/marker asserted and all three mutating methods are absent from `_CappedErrors` (C:1694-1704). |
| R-A2L-READ.66/1 | C::test_cov_read_66_log_line | full | Parser and real app log method assert capped single-line/no-ESC output (C:1713-1745). |
| R-A2L-READ.66/3 | R::test_r_a2l_read_66_esc_in_echoed_word | partial | U+FFFD echo is asserted only by substring; exact Line 23 is not (R:466-470). |
| R-A2L-001.2/3 | C::test_cov_001_2_matrix_dim_comment_not_read | full | Commented MATRIX_DIM ignored; product 4 and length 8 asserted (C:283-287). |
| R-A2L-READ.7/1 | C::test_cov_read_7_comment_between_digits_separate_word | full | Address and separate deposit word `4026` asserted (C:290-299). |
| R-A2L-READ.7/4 | R::test_r_a2l_read_7_comment_glued_splits | false-premise | The original audit was wrong: RP-B4 `ECU_ADDRESS/*c*/0x1234` and address 0x1234 were already exact at R:526-536, especially R:530. |
| R-A2L-READ.7/6 | C::test_cov_read_7_keyword_glued_comment_upper_limit | full | Upper limit 65535 and BIT_MASK 0x0FF0 both asserted (C:321-327). |
| R-A2L-READ.8/2 | C::test_cov_read_8_comments_do_not_nest_word_c | full | `c` is asserted in X's own section words and stray-close error is present (C:330-339). |
| R-A2L-READ.9/2 | C::test_cov_read_9_lone_line_end_terminator | partial | The embedded CRLF is still followed by `.replace("\n", nl)`, producing CR-CR-LF for the CRLF arm (C:269-275); the required isolated terminator is not tested. |
| R-A2L-READ.10/1 | C::test_cov_read_10_comment_not_closed_line_20 | full | Exact Line-20 error and no X tag asserted (C:348-353). |
| R-A2L-READ.11/1 | C::test_cov_read_11_stray_close_line_20 | full | Exact Line-20 stray-close diagnostic asserted (C:356-359). |
| R-A2L-READ.11/2 | C::test_cov_read_11_nested_stray_close_line_22 | full | Exact Line-22 nested-comment diagnostic asserted (C:362-366). |
| R-A2L-001.3.2/1 | C::test_cov_001_3_2_escape_long_identifier | full | Address and exact `C:\\` long identifier asserted (C:374-380). |
| R-A2L-001.3.2/4 | C::test_cov_001_3_2_backslash_line_end_exact | partial | The required standalone three-line shape expects Line 3, but this test wraps it in HDR and asserts Line 25 (C:383-388); no ruling changed this case's fixture. |
| R-A2L-READ.13/3 | C::test_cov_read_13_exactly_one_tag | full | Exactly one total tag and no Q asserted (C:415-420). |
| R-A2L-READ.14/1 | C::test_cov_read_14_multiline_string_one_word | partial | Despite its name, the node again asserts only later BIT_MASK; it never asserts that the multiline ANNOTATION_TEXT is one word (C:423-438). |
| R-A2L-READ.14/2 | C::test_cov_read_14_words_after_close_carry_end_line | full | Documented standalone line-1 fixture asserts end_line 5, Line-5 U+00E9, and no Line-4 error (C:441-451). |
| R-A2L-READ.15/1 | C::test_cov_read_15_quoted_string_not_closed_line_22 | full | Exact Line-22 unclosed-string error asserted (C:454-457). |
| R-A2L-001.1/1 | C::test_cov_001_1_if_data_parentage | full | IF_DATA child relationship and SX BIT_MASK asserted (C:465-474). |
| R-A2L-001.1/3 | C::test_cov_001_1_end_after_words_closed_zero_errors | partial | Tag and zero errors asserted, but the required closure on that same line/`end_line` is not (C:477-482). |
| R-A2L-001.1/4 | C::test_cov_001_1_two_one_line_instances | full | Two INSTANCE sections, equal start/end lines, both spans, tag address, and zero errors asserted (C:485-500). |
| R-A2L-READ.19/1 | C::test_cov_read_19_begin_glued_exact; H | full | No X section asserted (C:503-508); H's exact RP-B31 REF comparison supplies complete section and exact line/error equality. |
| R-A2L-READ.19/2 | C::test_cov_read_19_endx_closes_at_own_end | partial | `/endX` ownership is asserted, but X's closing `end_line` at its own `/end` is not (C:511-518). |
| R-A2L-READ.54/1 | C::test_cov_read_54_compu_method_named_later_full | full | Later CM_LIN resolves; raw 5 → physical 10 with conversion `ok` (C:1753-1773). |
| R-A2L-READ.54/3 | C::test_cov_read_54_record_layout_named_later | full | Later RL_K1 FNC_VALUES UWORD and CRL length 2 asserted (C:1781-1793). |
| R-A2L-001.4/1 | R::test_r_a2l_001_4_stray_end | partial | Stray `/end X` checked only by message substring; exact Line 30 absent (R:818-823). |
| R-A2L-001.4/2 | R::test_r_a2l_001_4_stray_end | partial | `junk /end X` checked only by message substring; exact Line 30 absent (R:818-823). |
| R-A2L-001.5/1 | R::test_r_a2l_001_5_end_name_mismatch; C::test_cov_read_21_innermost_close_line; E::test_e5_p4_end_mismatch_uses_end_word_line | partial | Required shape checks mismatch only by substring (R:826-833; C:1851-1855); E checks end-word identity on a different Line-22 shape, not required Line 23 (E:133-145). |
| R-A2L-001.5/2 | R::test_r_a2l_001_5_end_name_mismatch | partial | Reverse mismatch remains a substring assertion without exact Line 23 (R:831-833). |
| R-A2L-READ.22/1 | C::test_cov_read_22_include_exactly_one | full | Exactly one include error and unquoted filename asserted (C:521-526). |
| R-A2L-READ.22/2 | C::test_cov_read_22_include_comment_zero_errors | full | Commented include asserts zero errors (C:529-532). |
| R-A2L-READ.64/1 | C::test_cov_read_64_32_levels_exact | partial | Exact cap error asserted, but required zero sections and zero tags are not (C:535-544). |
| R-A2L-READ.64/2 | C::test_cov_read_64_32_levels_exact | partial | One-line cap error asserted, but required zero sections is not (C:538-544). |
| R-A2L-READ.64/3 | C::test_cov_read_64_32_levels_exact | full | Exact depth 32 and no errors asserted (C:545-553). |
| R-A2L-READ.65/1 | C::test_cov_read_65_nesting_renders; C::test_cov_read_65_one_line_5000 | full | One-per-line and one-line 5,000 forms parse/render with exact cap errors (C:556-572); the matrix does not require the audit's extra “closed” variant. |
| R-A2L-READ.65/2 | C::test_cov_read_65_nesting_renders | full | 50,000 unclosed begins parse/render with exact Line-33 cap error (C:556-564). |
| R-A2L-READ.65/3 | C::test_cov_read_65_stray_end_flood_renders | full | 200,000 stray ends parse/render and cap length is asserted (C:575-579). |
| R-A2L-READ.65/5 | R::test_r_a2l_read_65_no_exception_one_line_string | partial | The 10 MB string is parsed/rendered, but no assertion proves it remains one word (R:894-898). |
| R-A2L-READ.65/6 | P::test_r_a2l_read_52_words_no_exception_and_one_error | partial | Only the 600,000-line form is parsed; there is no render and no 4.8-million-word one-body-line variant (P:263-271). |
| R-A2L-READ.23/5 | C::test_cov_read_23_two_measurements_full | full | Both addresses/datatypes/lengths, no UNKNOWN, and no duplicate-symbol error asserted (C:587-598). |
| R-A2L-READ.25/5 | C::test_cov_read_25_header_address_k2 | full | UWORD, length 2, and address 0x1234 asserted (C:601-605). |
| R-A2L-READ.26/3 | H | full | Exact RP-B21 and Inc-2 A4 shapes are in the hostile corpus (C:1354,1422); REF compares address and deposit. |
| R-A2L-READ.26/4 | C::test_cov_read_26_header_full | full | K3 kind/address/deposit, length 2, and little byte order asserted (C:608-615). |
| R-A2L-READ.27/1 | C::test_cov_read_27_case07_full | partial | The test uses non-None address/length and mere key presence for limits/unit, not each tag's written e07fb00 values (C:618-625). |
| R-A2L-READ.27/4 | C::test_cov_read_27_extension_byte_order_keywords | full | K3 header fields and little effective byte order asserted (C:628-634). |
| R-A2L-READ.28/1 | C::test_cov_read_28_short_header_exact_lines | full | Exact begin-line five-of-six error asserted (C:637-643). |
| R-A2L-READ.28/2 | C::test_cov_read_28_short_header_exact_lines; H | full | Focused short-header/no-field assertions exist (C:644-649); H3e's sibling H3c exact corpus shape supplies the required quoted `Synthetic map` line/error via REF. |
| R-A2L-READ.28/4 | C::test_cov_read_28_short_header_exact_lines | full | Exact begin-line four-of-six error and length 2 asserted (C:650-654). |
| R-A2L-READ.29/4 | C::test_cov_read_29_matrix_dim_product | full | MATRIX_DIM 6 and length 12 asserted (C:657-661). |
| R-A2L-READ.29/5 | C::test_cov_read_29_keyword_not_argument_b8_b9; H | full | Own byte order absence asserted (C:664-673); H's exact B8 comparison also asserts address None and complete tag fields/errors. |
| R-A2L-READ.30/1 | C::test_cov_read_30_byte_order_address | full | Address 0x1234 and little byte order asserted (C:676-680). |
| R-A2L-READ.30/3 | C::test_cov_read_30_k5_zero_errors | full | K5 address 0x18 and zero errors asserted (C:683-689). |
| R-A2L-READ.32/1 | C::test_cov_read_32_duplicate_exact_lines | full | Exact duplicate Line 23 and disagreement Line 20 plus no address asserted (C:707-714). |
| R-A2L-READ.32/2 | C::test_cov_read_32_duplicate_exact_lines | partial | Matrix requires second BYTE_ORDER on line 23; test adds it after ECU_ADDRESS and asserts Line 24 instead (C:715-718), without a corrected ruling. |
| R-A2L-READ.32/3 | C::test_cov_read_32_duplicate_exact_lines; H | full | No address asserted (C:719-722); exact Inc-2 P corpus shape supplies REF line/error equality for duplicate BIT_MASK. |
| R-A2L-READ.58/1 | C::test_cov_read_58_argument_count_exact_lines | full | B8/B9 exact keyword-line diagnostics asserted (C:725-732). |
| R-A2L-READ.58/2 | C::test_cov_read_58_argument_count_exact_lines | full | All three short-keyword diagnostics, including third bare ECU_ADDRESS, have exact lines (C:733-741). |
| R-A2L-READ.58/3 | R::test_r_a2l_read_58_argument_count_errors | partial | MATRIX_DIM zero/four-argument errors remain substring-only, with no exact keyword lines (R:1129-1132). |
| R-A2L-READ.58/5 | R::test_r_a2l_read_58_argument_count_errors; C::test_cov_read_58_hex_like_surplus_exact | partial | New node covers round-3 shapes exactly (C:744-764), but required round-2 ECU_ADDRESS/LENGTH/BIT_MASK surplus diagnostics remain substring-only or absent (R:1133-1137). |
| R-A2L-READ.59/1 | C::test_cov_read_59_declares_exact_lines | full | Both disagreeing-address diagnostics assert exact Line 20 (C:772-780). |
| R-A2L-READ.59/2 | C::test_cov_read_59_all_five_size_shapes | full | All five required size pairs asserted (C:785-796). |
| R-A2L-READ.60/2 | C::test_cov_read_60_no_address_all_shapes | partial | Missing-argument shape asserts address None but never preserves/asserts BIT_MASK 0x0FF0 (C:904-922, especially C:911,916-919). |
| R-A2L-READ.60/4 | C::test_cov_read_60_no_address_all_shapes | partial | Only agreeing ECU_ADDRESS duplicates are checked (C:920-922); agreeing header-address and BIT_MASK pairs and duplicate errors are absent. |
| R-A2L-READ.60/6 | C::test_cov_read_60_no_address_all_shapes; C::test_cov_read_58_argument_count_exact_lines | partial | Both no-address shapes exist (C:912-913), but the missing-BIT_MASK shape has no corresponding .58 diagnostic assertion. |
| R-A2L-READ.60/8 | C::test_cov_read_60_hex_surplus_address_none; C::test_cov_read_60_08_patch_editor_refuses_hex_surplus | partial | Eight fail-closed addresses and `resolve_symbol_entry` are asserted (C:925-940,1237-1260); required real “Use parameter” picker listing is absent. |
| R-A2L-READ.60/9 | C::test_cov_read_60_byte_order_source_not_byte_order; C::test_cov_read_68_inherited_byte_order_once | partial | Own/layout invalid sources are covered, but inherited-MOD_COMMON address refusal is not asserted and the holding case uses valid MOD_COMMON rather than required invalid source (C:943-961,1031-1056). |
| R-A2L-READ.62/1 | C::test_cov_read_62_deposit_none; H | full | All three fields are None (C:964-969); H3c's exact REF comparison supplies the associated .28 error. |
| R-A2L-READ.62/2 | C::test_cov_read_62_deposit_none | full | One-word header asserts address/kind/deposit None (C:970-972). |
| R-A2L-READ.67/1 | C::test_cov_read_67_not_closed_exact_lines | full | Exact Line-20 not-closed and unclosed-section errors asserted (C:1006-1012). |
| R-A2L-READ.67/2 | C::test_cov_read_67_not_closed_exact_lines | full | Exact comment/begin lines and zero X tags asserted (C:1013-1017). |
| R-A2L-READ.68/1 | C::test_cov_read_68_byte_order_error_exact | full | Four invalid words each assert exactly one exact Line-23 error and no address (C:1020-1028). |
| R-A2L-READ.63/1 | C::test_cov_read_63_exact_words_and_lines | full | Six exact echoed words/lines including fullwidth replacement asserted (C:989-997). |
| R-A2L-READ.63/3 | C::test_cov_read_63_exact_words_and_lines | full | Four exact size-word diagnostics asserted (C:998-999). |
| R-A2L-READ.63/4 | C::test_cov_read_63_exact_words_and_lines | full | Both MATRIX_DIM shapes, including `2 x 3`, assert exact error text (C:1000-1003). |
| R-A2L-READ.69/3 | C::test_cov_read_69_above_64_bits_no_error | full | Header overflow asserts no address and no `is not a number` (C:1106-1109). |
| R-A2L-READ.37/2 | C::test_cov_read_37_matrix_dim_product_tracked | full | MATRIX_DIM 4 and length 8 asserted (C:1117-1120). |
| R-A2L-READ.38/2 | C::test_cov_read_38_ascii_number_overflow; R::test_r_a2l_read_38_length_bounds | full | New ASCII overflow shape asserts no length (C:1123-1126); existing two LENGTH overflows remain asserted (R:1361-1365). |
| R-A2L-READ.39/1 | R::test_r_a2l_read_39_length_error; C::test_cov_read_39_ascii_number_error; H | partial | All four messages now have inputs, but focused assertions omit exact Line 20 (R:1368-1372; C:1129-1132); H covers only its corpus shapes, not LENGTH 0/1048577. |
| R-A2L-013/2 | C::test_cov_read_013_agree_no_declares | full | Length 4 and zero `declares the sizes` errors asserted (C:1135-1141). |
| R-A2L-READ.61/1 | R::test_r_a2l_read_61_no_length_when_disagree; C::test_cov_read_59_undeclared_layout_val_blk | partial | Six known-layout disagreements assert no length (R:1416-1429), but the added undeclared-layout VAL_BLK checks only its error, not length None (C:799-804). |
| R-A2L-READ.61/3 | C::test_cov_read_61_agreeing_lengths | full | All four agreeing sets, including ASCII NUMBER/MATRIX_DIM, assert exact lengths (C:1158-1168). |
| R-A2L-READ.61/9 | C::test_cov_read_61_no_enriched_byte_size_all_shapes; C::test_cov_read_61_09_patch_editor_refuses | partial | Four enriched rows assert all three fields None (C:1207-1222), and one Patch backend refusal exists (C:1225-1234); all four real picker arms and Check Editor route are absent. |
| R-A2L-READ.48/1 | R::test_r_a2l_read_48_tracked_files_equal_ref | partial | Full tracked REF comparison exists, but no elapsed-time assertion enforces ≤120 seconds (R:1634-1644). |
| R-A2L-READ.49/2 | R::test_r_a2l_read_49_2_defect_classes_hand_written | partial | D8 CUBOID reduction now asserts 36 (R:1796-1820), but D5 still uses `RL_SWORD`, not required `RL.FNC.SWORD.ROW_DIR` (R:1776-1783), so name-independent datatype precedence is not isolated. |
| R-A2L-READ.50/1 | C::test_cov_read_50_summary_exact | partial | Comment removal and a VALUE suffix are asserted, but not the complete XH section line with `- CHARACTERISTIC XH "one-line header" ...` (C:1602-1609). |
| R-A2L-READ.51/1 | C::test_cov_read_51_control_chars_fffd_and_no_broken_lines | full | Nine controls assert U+FFFD and an explicit empty broken-line list (C:1652-1660). |
| R-A2L-076/1 | C::test_cov_read_076_077_exact | full | merge_inc_test parse-errors index precedes sections index (C:1623-1629). |
| R-A2L-076/2 | C::test_cov_read_076_077_exact | full | Inline error/sections/tags strict ordering asserted (C:1630-1636). |
| R-A2L-077/1 | C::test_cov_read_076_077_exact | full | Errors→sections→tags and complete `mem=unknown` tag line asserted (C:1630-1637). |
| R-A2L-READ.52/1 | P::test_r_a2l_read_52_case06_time; P::test_r_a2l_read_52_software_a_time; P::test_r_a2l_read_52_case06_memory; P::test_r_a2l_read_52_software_a_memory | full | Static protocol uses three fresh processes, medians, same-session base when supplied, bounds, and pre/peak-delta reporting (P:119-189,193-238). Runtime is RED: case_06 12.714 s > 10.580 s; not verified. |
| R-A2L-READ.52/2 | P::test_r_a2l_read_52_string_time; P::test_r_a2l_read_52_string_memory | full | Static fresh-process median/base/bound/RSS protocol is present (P:210-216,241-249). Arms passed in the perf transcript, but READ.52 is not declared verified while its family run is red. |
| R-A2L-READ.52/3 | P::test_r_a2l_read_52_words_memory; P::test_r_a2l_read_52_words_no_exception_and_one_error | full | Memory protocol plus exact one-Line-11 surplus diagnostic and no address asserted (P:252-271). Arms passed, but no READ.52 verified claim is made from the red family run. |

## Corrected premises and oracle checks

- **160 forms, 159 comparisons + control:** the records agree at `02-test-cases.md:17-25`, `:288`, `01-requirements.md:258`, and `codewire/graph-inc11.md:799`. C:1284-1286 enumerates 31+40+47+4+20+9+9 = 160. C:1538 asserts 160; C:1545-1555 handles two UTF-16 refusals and H3e; C:1565 asserts 157 ordinary REF comparisons, so 157+2+H3e = 160 and 159 differential comparisons include the two direct UTF-16 refusal arms. H3e keeps address, no length, and counts 7/9.
- **READ.4/5:** C:228-240 implements line 20 for the CHARACTERISTIC address and line 23 for LENGTH/MATRIX_DIM, matching `02-test-cases.md:45`.
- **READ.14/2:** C:441-451 is the standalone line-1 fixture and asserts end_line/error line 5.
- **Mixed line ends:** C:148-154 selects CR for empty lines and therefore does not fuse a preceding CR with an empty line's LF. This correction does not fix the separate READ.9/2 fixture at C:269-275.
- **REF independence and corrections:** the static guard rejects product imports and shared long strings (C:64-92). Quoted positional tokens and unquoting are implemented at `tests/support/b103_a2l_ref.py:201-208`, `:622-644`, and `:652-704`; header-address source line at `:1020-1030`; invalid ECU_ADDRESS fail-closed handling at `:1045-1070`; disagreeing duplicate BIT_MASK refusal at `:1148-1161`.
- **P16/P17 actual locations:** P16 is `E::test_e5_p16_curve_declared_uword_two_axis_points_full_span` (E:431). P17 is not in E; its product-route coverage is `C::test_cov_read_54_compu_vtab_named_later` (C:1796-1819). The final combined transcript covers both files.

## Runtime transcripts and limits

- `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/coverage-and-e5-green.txt:1-5` — scratch package path printed first, **136 passed**, `PYTEST_EXIT=0`. This is the final C+E run (112 C nodes + 24 E nodes); it is not a perf run and does not erase static partials.
- `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/coverage-hostile-green.txt:1-4` — hostile differential green, `PYTEST_EXIT=0`.
- `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/coverage-perf.txt:7-37` — **6 passed, 1 failed, 1 deselected**, `PYTEST_EXIT=1`; case_06 time 12.714064 s exceeds 10.579511 s. READ.52 is therefore not verified and E5 is not globally green.
- `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/coverage-tests-4.txt:1-58` — earlier 112-node C run, 111 passed/1 failed; retained as history, not used as green evidence.
- `.dev-flow/2026-11-05-batch-103/inc-11/evidence-e5/p16-green.txt:1-4` — focused P16 green.

No `verified` result-cell upgrade is authorized by this report. The 37 partial rows need their named residual assertions/routes and Linux evidence; READ.52 needs a clean same-session perf run, at minimum a passing case_06 time arm. The matrix still contains stale `full/covered/verified` claims and mostly legacy node references; those cells require orchestrator ownership.
