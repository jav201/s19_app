# Inc 11 E5: mutant table B — tags, lengths and declared spans

Baseline `f1397097`. Work done only in an isolated git clone at
`C:\Users\jjgh8\AppData\Local\Temp\b103-e5-11-mutB` (MSYS `/tmp/b103-e5-11-mutB`);
the real worktree was never mutated and nothing was committed. The clone was a
`git clone --local --single-branch --branch b103-inc11-code` of the main repo, so
`git ls-files` (used by `_tracked_a2l()`) resolves inside the copy.

Host: Windows, Python 3.12.7 (anaconda), pytest 8.3.4. Every arm ran with
`PYTHONDONTWRITEBYTECODE=1`, closed stdin and an isolated `HOME` / `XDG_*` /
`LOCALAPPDATA` under `…/b103-e5-11-mutB-evidence/zq_iso_user`.

Verdicts: **KILLED** = the discriminating test node failed on an assertion;
**SURVIVED** = it still passed; **CRASH** = collection/import error; **BAD** = the
anchor applied zero times. A process exit code alone was never counted — each
transcript shows the pytest short-summary line and the assertion.

## Baseline

`tests/test_b103_a2l_reader.py` + `tests/test_b103_a2l_definition.py`
(`-m "not slow"`): **372 passed, 2 failed**. The 2 failures are Windows-only
environmental failures, present in the pristine clone before any mutation and
caused by `Path.write_text` translating `\n` → `\r\n` on Windows, which corrupts
the *mixed* line-ending fixtures:

- `test_r_a2l_read_1_crlf_cr_mixed_read_as_lf`
- `test_r_a2l_read_1_cr_cr_lf_counts_two_ends`

They exercise R-A2L-READ.1 (mixed CR/CRLF), not any mutated function, and are
outside this table's target (`_tag_header`, `_tag_keyword_lines`, `_number_word`,
`_tag_sizes`, `extract_a2l_tags`, `extract_declared_spans`, `_describe_one`).
After every mutant was restored, `git diff --stat` was empty and the slice
re-ran to the same 372/2.

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
| M09 | R-A2L-READ.61 (E3S-23) | CURVE/MAP refusal not final: inline-axis span re-derives a refused length | `            and tag.get("length") is None\n            and id(tag) not in refused_length_ids\n            and span is not None` | `test_r_a2l_read_48_tracked_files_equal_ref` | 1 | **SURVIVED** |
| M10 | R-A2L-READ.68 / .60 | byte order: an invalid BYTE_ORDER word keeps the address | `            _errors.append(f"Line {own_bo_line}: BYTE_ORDER {_echo_word(own_bo_word)} is not a byte order")\n            address_invalid = True` | `test_r_a2l_read_68_byte_order_error` | 1 | KILLED |
| M11 | R-A2L-READ.42 | forward typedefs: the typedef pre-pass is removed (`_collect_typedefs([])`) | `    _collect_typedefs(sections)` | `test_r_a2l_read_42_instance_forward_typedef_ref` | 1 | KILLED |
| M12 | R-A2L-READ.43 / .45 | unresolvable deposit: an unsizeable VALUE typedef guesses length 1 | `                if base is None:\n                    return None` | `test_r_a2l_read_45_instance_unresolvable_value_deposit_ref` | 1 | KILLED |
| M13 | R-A2L-READ.46 | BLOB bounds: BLOB size word no longer bounded | `"length": _bounded_length(length)` | `test_r_a2l_read_46_span_length_bounds` | 1 | KILLED |
| M14 | public export | public export: `extract_declared_spans` dropped from `a2l_extract` | `from .a2l import enrich_a2l_tags_with_values, extract_a2l_tags, extract_declared_spans` | `test_extract_declared_spans_is_public` | 1 | KILLED |

## Totals

- Arms: 15 (1 known-bad control + 14 mutants).
- KILLED: 14 (CONTROL, M01–M08, M10–M14).
- SURVIVED: 1 (M09).
- CRASH: 0.
- BAD: 0 (every anchor applied exactly once; applied count == table count on all arms).

The known-bad control is KILLED, so the harness itself is proven able to fail.

## Survivor

**M09 — R-A2L-READ.61 (E3S-23): "a refusal is final; the CURVE/MAP span step must not run after a refusal".**

Mutation: the inline-axis span step drops the `and id(tag) not in refused_length_ids`
guard, so a CURVE/MAP whose length was refused re-derives it from its inline span.

Evidence (see `mutants-B/M09.txt` and the probe transcript
`mutants-B/M09-probe.txt`): `test_r_a2l_read_48_tracked_files_equal_ref` passes
`1 passed in 30.93s` — no tracked file has a CURVE/MAP with *both* a refused
length and an inline span, so the oracle never exercises the guard. A synthetic
MAP with `LENGTH 0` and one inline `STD_AXIS` proves the fault is real:

- baseline: `length: None`, error `Line 8: CHARACTERISTIC C declares the sizes 0 and 13`;
- with M09: `length: 13` (the refused length is re-derived from the span).

## Test gap

The refusal-is-final contract for the inline-axis span step (R-A2L-READ.61,
E3S-23: "the CURVE/MAP span step run after a refusal → `LENGTH 2264` gives 2266")
has **no direct synthetic test**. It is only indirectly reachable through the
35-file reference oracle, which does not contain the triggering shape (a
CURVE/MAP with a refused `DATA_SIZE`/`LENGTH` *and* inline axes). A small
synthetic case (a MAP/VAL_BLK-free MAP with inline `STD_AXIS` + `LENGTH 0`, or
`LENGTH 2264` against a 2266 span) would kill M09. Per the brief this is a
finding for the orchestrator; the source was not changed to kill the survivor.

## Runner transcripts

Under `mutants-B/`: one file per arm (`CONTROL.txt`, `M01.txt` … `M14.txt`),
plus `M09-probe.txt` (the synthetic MAP repro proving M09 is a live fault) and
`final-green-full.txt` (the aborted full-suite attempt — the full suite exceeds
20 min on this host; the slice re-run of reader+definition, 372 passed / 2
Windows-env failures, is recorded in `final-green-slice.txt`).
