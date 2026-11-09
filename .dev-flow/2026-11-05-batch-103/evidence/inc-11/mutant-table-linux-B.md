# Inc 11 E5: mutant table B — tags, lengths and declared spans (Linux re-run)

Canonical re-run on the current frozen tree `P19 + corrected REF`
(`/tmp/b103-e5-11-mutB-rtx/tree`). The Windows table
`/tmp/b103-e5-11-mutB-rtx/mutant-table-B.windows.md` was read only as
non-canonical reference; every anchor and verdict below is rebuilt from the
current tree.

Host: `cachyos-rtx`, Linux 7.3.3-1-cachyos x86_64. Python 3.11.18
(`/home/javiergr/miniconda3/envs/s19ci/bin/python -I -B`), pytest 8.4.2.
Every arm ran with `PYTHONDONTWRITEBYTECODE=1`, closed stdin, an isolated
`HOME` / `XDG_CACHE_HOME` / `XDG_CONFIG_HOME` / `XDG_DATA_HOME` /
`LOCALAPPDATA` under `/tmp/b103-e5-11-mutB-rtx/zq_iso_user`, and
`s19_app.__file__` printed first in every transcript. One mutation at a time;
bytes restored and the SHA-256 verified against the pre-mutation hash after
every arm (no git checkout/stash/commit).

Verdicts: **KILLED** = the discriminating test node failed on an assertion;
**SURVIVED** = it still passed; **CRASH** = collection/import error;
**BAD** = the anchor applied zero times. A process exit code alone was never
counted — each transcript shows the pytest short-summary line and the
assertion. All anchors applied exactly once; applied count == table count on
every arm.

## Baseline

`tests/test_b103_a2l_reader.py` + `tests/test_b103_a2l_reader_e5.py` +
`tests/test_b103_a2l_reader_coverage.py` +
`tests/test_b103_a2l_definition.py`: **522 passed in 341.68s** (Linux, exit 0).
The two Windows-only CR/CRLF fixture failures from the Windows reference do not
occur on Linux. After all mutants were restored, `git diff --stat` was empty and
the slice re-ran to the same 522/0 (final green, `out/final-green.txt`).

## Table

| ID | Requirement | Mutation | Exact unique anchor | Expected discriminating test | Applied | Verdict |
|---|---|---|---|---|---|---|
| CONTROL | R-A2L-READ.34 | known-bad control: `_number_word` always refuses (guard `if True`) | `    if not _NUMBER_WORD_RE.fullmatch(word):` | `test_r_a2l_read_34_hex_words` | 1 | KILLED |
| M01 | R-A2L-READ.27 | header boundary: keyword-stop removed, header read by count only | `        if not quoted and word in _TAG_KEYWORD_ARITY:` | `test_r_a2l_read_27_keyword_ends_header` | 1 | KILLED |
| M02 | R-A2L-READ.28 | header arity: MEASUREMENT↔CHARACTERISTIC header-word counts swapped | `        header_m = 6 if section_name == "MEASUREMENT" else 7` | `test_r_a2l_read_28_short_header_error` | 1 | KILLED |
| M03 | R-A2L-READ.68 | keyword case: byte-order word normalization no longer case-insensitive (`.upper()` dropped) | `    raw = (token or "").strip().upper()` | `test_r_a2l_read_68_byte_order_words_no_error` | 1 | KILLED |
| M04 | R-A2L-READ.35 | number bounds: decimal word parsed base-0 (`010` → 8) | `    return int(word, 10)` | `test_r_a2l_read_35_decimal_words` | 1 | KILLED |
| M05 | R-A2L-READ.34 | number bounds: uppercase `0X` prefix refused | `_NUMBER_WORD_RE = re.compile(r"0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,20}")` | `test_r_a2l_read_34_hex_words` | 1 | KILLED |
| M06 | R-A2L-READ.69 | address bounds: `2^64-1` now refused (cap lowered by 1) | `_MAX_ADDRESS = 0xFFFFFFFFFFFFFFFF` | `test_r_a2l_read_69_address_above_64_bits` | 1 | KILLED |
| M07 | R-A2L-READ.59 / .61 | sizes that stop agreeing: `_tag_sizes` always returns "agree" | `    return smallest == largest, smallest, largest, no_number` | `test_r_a2l_read_61_no_length_when_disagree` | 1 | KILLED |
| M08 | R-A2L-READ.38 / .61 | `_describe_one` refills a missing length with `1` | `    byte_length = tag.get("length")` | `test_r_a2l_read_38_definition_stays_refused` | 1 | KILLED |
| M09 | R-A2L-READ.61 (E3S-23) | final refusal broken: the CURVE/MAP span no longer joins the `_tag_sizes` agreement check, so a refused `LENGTH 0` re-derives from the inline span | `    if kind in _CURVE_MAP_FAMILY:`<br>`        values = list(byte_sizes)`<br>`        if span is not None:`<br>`            values.append(span)` | `test_e5_p15_length_zero_inline_axis_refusal_final` | 1 | KILLED |
| M10 | R-A2L-READ.68 / .60 | byte order: an invalid own BYTE_ORDER word keeps the address | `        if own_bo_word is not None and own_bo_order is None:`<br>`            address_invalid = True` | `test_r_a2l_read_68_byte_order_error` | 1 | KILLED |
| M11 | R-A2L-READ.42 | forward typedefs: the typedef pre-pass is removed (`_collect_typedefs([])`) | `    _collect_typedefs(sections)` | `test_r_a2l_read_42_instance_forward_typedef_ref` | 1 | KILLED |
| M12 | R-A2L-READ.43 / .45 | unresolvable deposit: an unsizeable VALUE typedef guesses length 1 | `                if base is None:`<br>`                    return None` | `test_r_a2l_read_45_instance_unresolvable_value_deposit_ref` | 1 | KILLED |
| M13 | R-A2L-READ.46 | BLOB bounds: BLOB size word no longer bounded | `"length": _bounded_length(length)` | `test_r_a2l_read_46_span_length_bounds` | 1 | KILLED |
| M14 | public export | public export: `extract_declared_spans` dropped from `a2l_extract` | `from .a2l import enrich_a2l_tags_with_values, extract_a2l_tags, extract_declared_spans` | `test_extract_declared_spans_is_public` | 1 | KILLED |
| P16 | R-A2L-018 | full-span precedence: a resolvable inline span exports the scalar element size instead of the full record span | `                if span is not None:`<br>`                    tag["length"] = span` | `test_e5_p16_curve_declared_uword_two_axis_points_full_span` | 1 | KILLED |
| P17a | R-A2L-DEF.2 | exact TAB_VERB: `_object_kind` no longer maps the exact `TAB_VERB` conversion to `enum` | `        if char_type == "VALUE":`<br>`            kind = "enum" if conversion_type == "TAB_VERB" else "number"` | `test_r_a2l_def_2_1_tab_verb_with_long_identifier_on_its_own_line_is_an_enum` | 1 | KILLED |
| P17b | R-A2L-DEF.13/1 | missing table (no `COMPU_TAB_REF`): the enum-table refusal guard also requires a non-None `enum_table`, so a `(none)` table is no longer refused | `    if refusal is None and kind == "enum":` | `test_r_a2l_def_13_1_enum_with_no_table_is_refused` | 1 | KILLED |
| P17c | R-A2L-DEF.13/2 | missing table (dangling `COMPU_TAB_REF`): the `table_form is None` branch is disabled, misclassifying a dangling table as empty | `        elif table_form is None:` | `test_r_a2l_def_13_2_dangling_table_is_refused` | 1 | KILLED |
| P17d | R-A2L-DEF.17 | missing entry: the `not enum_entries` branch is disabled, so an empty table is no longer refused | `        elif not enum_entries:` | `test_r_a2l_def_17_1_count_zero_is_refused` | 1 | KILLED |
| P17e | R-A2L-READ.54/4 | near-name exactness: `_object_kind` uses `startswith("TAB_VERB")`, misclassifying `TAB_VERB_RANGE` as enum | `conversion_type == "TAB_VERB"` (both scalar branches) | `test_cov_read_54_tab_verb_near_keyword_is_not_enum` | 2 | KILLED |
| P18a | R-A2L-READ.48 / CTX sizes | DATA_SIZE standing precedence: the standing-size branch is disabled, so a CURVE with `DATA_SIZE 4` and no span falls back to `None` instead of 4 | `                elif has_standing_size:` | `test_e5_p18_data_size_only_unresolved_span_uses_standing_size` | 1 | KILLED |
| P18b | R-A2L-READ.48 / CTX sizes | external agreeing span: the post-pass agreement check is forced to disagree, so an agreeing external full span is refused instead of exported | `            if not agree:` | `test_e5_p18_external_full_span_agrees_with_standing_data_size` | 1 | KILLED |

## Totals

- Arms: 23 (1 known-bad control + 14 reader mutants + 8 P-finding arms).
- KILLED: 23 (CONTROL, M01–M14, P16, P17a–P17e, P18a, P18b).
- SURVIVED: 0.
- CRASH: 0.
- BAD: 0 (every anchor applied exactly once; applied count == table count on all arms).

The known-bad control is KILLED, so the harness itself is proven able to fail.

## Survivors

None. In the Windows reference, M09 was SURVIVED because no tracked file carried a
CURVE/MAP with both a refused length and an inline span. In this corrected tree
the direct synthetic case `test_e5_p15_length_zero_inline_axis_refusal_final`
exists and M09 is now **KILLED** (assertion: `assert 13 is None`, i.e. the
mutant re-derived `length=13` from the inline span instead of keeping the final
refusal `None`).

## Test gaps

- **None open.** The former P17 exactness gap is closed by
  `test_cov_read_54_tab_verb_near_keyword_is_not_enum` and the P17e arm
  (`mutants-linux-B-P17-exactness.txt`): both scalar branches were mutated to
  `startswith("TAB_VERB")` (applied count 2), the test failed `enum != number`,
  and the restored baseline passed. The former M09 gap is closed by
  `test_e5_p15_length_zero_inline_axis_refusal_final`. Every arm in this table
  is killed by a direct, assertion-checked test node.

## Runner transcripts

Under `out/mutants-B/`: one file per arm (`CONTROL.txt`, `M01.txt` …
`M14.txt`, `P16.txt`, `P17a.txt` … `P17e.txt`, `P18a.txt`, `P18b.txt`). The
baseline transcript is `out/baseline.txt` and the final green re-run is
`out/final-green.txt`. P17e's separate mutation/restoration transcript is
`mutants-linux-B-P17-exactness.txt`.
