# Inc 11 E5: findings and corrective rulings (orchestrator, 2026-11-08)

E5 is **FAIL** at this gate. The independent code, security and coverage reviews are preserved as `E5-code-review.md`, `E5-security.md` and `E5-coverage-audit.md`. No validation record or merge is authorized yet.

## Product findings accepted for test-first reproduction

Each item must first produce a behavioral RED on `f1397097` through the relevant public route. A finding that does not reproduce must be reported, not “fixed” by inference.

- **P1 — quoted numeric words.** `_tag_header` must preserve quoted status through `_number_word`; quoted addresses, sizes and lengths give no number. Affected: R-A2L-READ.34–.36, .40, .41 and .63.
- **P2 — backslash plus line end in a quoted string.** The bounded quoted-word reader must consume backslash-LF/CRLF/CR without allowing structural `/begin` or `/end` words to escape. Affected: R-A2L-001.3.2 and READ.13/.14.
- **P3 — nested MODULE byte-order source.** A MODULE without its own BYTE_ORDER carries the enclosing source, including invalid-source refusal; it does not reset to little. Reproduce through nested modules and the public tag reader.
- **P4 — structural line identities.** `end_line` and `/end` diagnostics use the `/end` word's line, while the nesting-cap error uses the `/begin` word's line, not a later section-name line.
- **P5 — multiline comment boundaries.** Pending words are flushed at every non-string element boundary before the line advances; words after a later comment close cannot join the earlier line's run.
- **P6 — quoted keyword arguments.** Canonical keyword items must not be split naively. Preserve argument boundaries and source lines; numeric and byte-order words keep their quoted status, while string-valued fields unquote correctly. This is an implementation correction to existing READ.29/.33 and quoted-string contracts, not a new feature.
- **P7 — external-axis diagnostic line.** Carry the section's local `start_line` into the post-pass so a standing-size disagreement never says `Line None`; do not add a public tag key.
- **P8 — argument diagnostic lines.** Number/BYTE_ORDER/MATRIX_DIM errors name the offending argument's line, not merely the keyword's line.
- **P9 — independent disagreement reporting.** Address and size disagreements are diagnosed independently of unrelated invalid byte-order/number conditions before the combined refusal.
- **P10 — every invalid BYTE_ORDER argument.** Validate each entry once for READ.68 even when duplicates/disagreements also occur.
- **P11 — typedef span refusal.** Declared-span inference applies the same `_tag_sizes` agreement/no-number gate as tags. A refused typedef length cannot reappear through `_infer_length_characteristic` or INSTANCE multiplication.
- **P12 — declared layout datatype precedence.** Resolve FNC_VALUES/declared layout datatype first and use the deposit-name hint only when that yields none, consistently in inference and agreement checks.
- **P13 — CUBOID/CUBE_4/CUBE_5.** Use `_CURVE_MAP_FAMILY` consistently for span resolution, standing-size checks and external-axis refusal, not only CURVE/MAP.
- **P14 — unclosed declared sections (design addendum required).** Before code, add an explicit requirement/case: an unclosed BLOB/INSTANCE exports no usable address or length, and an unclosed typedef cannot size an INSTANCE. Assign R-A2L-READ.70 and update the graph and test-case ledger. This is a security/consumer-contract correction; do not silently change only code.

## Coverage findings accepted

- Correct the two AT matrix node ids to the real functions; their `full/covered/verified` status stands.
- Repair R-A2L-READ.51/1's unescaped pipe and malformed row without weakening the expected observable.
- The audit counts 27 missing and 109 partial requirement cases incorrectly marked full. These are test-coverage implementation gaps. Complete the named inputs/assertions through product routes; do not simply downgrade them to make the gate pass. Broad differential tests may prove a case only when they assert the case's exact observable.
- READ.52's protocol must use same-session base/current fresh-process medians and report pre-parse RSS and peak-minus-before, in addition to the existing bound checks.
- Every changed case must be re-audited after correction. The two real-app ATs remain full.

## Mutants and platform discipline

- Unit A ran its pytest arms on Windows, contrary to the batch rule. Its Windows transcripts are non-canonical supporting material only; the final mutation verdict must be re-run on the Linux runner after corrections. The final-suite Windows RED is not a product regression.
- **M10 is provisionally not realisable on the public route.** Universal-newline file opening normalizes CR/CRLF before `_lex_a2l_lines`, and the only other caller passes canonical lines. Confirm this on Linux. If confirmed, record M10 as `not realisable`, not a product failure or a required source change; the public READ.1 tests already prove the required behavior.
- Unit B must also be checked for platform compliance. Any Windows-run arms are repeated on Linux after corrections.

## Corrective order

1. Preserve reviews and this ruling; repair matrix ids/row shape.
2. Add the READ.70 design addendum and all product-finding RED tests.
3. Fix product only where RED proves the finding, with independent test corrections in disjoint ownership.
4. Complete the 27 missing and 109 partial cases and READ.52's protocol.
5. Re-run integration, code/security/coverage re-reviews and both mutant units on Linux.
6. Only then write `04-validation.md`, run `trace_check`, and prepare the merge.

No integrated product or test edit starts until mutant unit B has finished its baseline work.
