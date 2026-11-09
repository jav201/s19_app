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
- **P15 — final tag-length refusal cannot be re-derived inline.** Mutant B M09 proves that removing the refused-length guard lets a MAP with `LENGTH 0` and an inline STD_AXIS recover length 13. Add the direct synthetic case and keep the inline-span pass subordinate to R-A2L-READ.61's final refusal.
- **P16 — resolved full family span takes precedence over scalar inference.** The E5 security re-review shows that generic `_infer_length_characteristic` can return the deposit element size before the resolved full span is assigned. For `_CURVE_MAP_FAMILY`, select the resolved full span first; when it cannot resolve, accept only a standing DATA_SIZE/LENGTH, not generic scalar inference. Preserve final refusals. Add a CURVE with declared UWORD and two axis points: full span 4, not scalar length 2.
- **P17 — TAB_VERB conversion is recognized and applied.** Coverage completion reproduced READ.54/4 RED: `CM_VT` had `conversion_type=None` and raw 1 remained 1 instead of `on`. Add TAB_VERB to the conversion-keyword census and resolve its referenced table through the existing enrichment route. An exact raw entry returns its text; a missing table or raw entry refuses conversion. This is an implementation correction to the existing READ.54/4 contract, not a new requirement.
- **P18 — standing DATA_SIZE and a subsequently resolved full span must not lose to scalar inference.** Both final reviews found that the family fallback called a LENGTH-only helper when only DATA_SIZE stood and that the external-axis post-pass preserved the provisional result. The public-route RED ran on the laptop (`lnx1`, Python 3.11.18): the unresolved-span case failed `None == 4`; the external-span case already passed on the current tree and is retained as a regression guard, not claimed as a second RED (`p18-red.txt`). `_infer_length_characteristic` and REF now accept DATA_SIZE/LENGTH consistently; the external post-pass preserves final refusals and assigns only a resolved, agreeing span. Focused GREEN is 2/2 (`p18-green.txt`); the complete E5+coverage run, including the 160,000-mutant node, is **148 passed** (`p18-e5-coverage-green-2.txt`).
- **P19 — READ.52 performance correction without a threshold change.** On the operator-provided alternative CachyOS runner (`lnx1`), case_06 initially failed at 10.461777 s against the same-session base 6.210491 s and bound 9.315736 s (`coverage-perf-laptop.txt`). An interleaved 6-pair probe still measured 1.672× (`read52-order-probe.txt`), ruling out measurement-order bias. The correction avoids reparsing already tokenized quote-free headers, caches pure number-word results with a 4096-entry bound, reuses the caller's resolved element size, skips inference when no dimensional keyword stands, and avoids irrelevant argument-list/duplicate-number work in `_tag_sizes`. The laptop run was **7 passed, 1 deselected**, all memory arms green, but case_06 had only **0.2 % margin** (9.296 / 9.313 s; `coverage-perf-laptop-green.txt`). On cachyos-rtx the first valid same-session base run still failed 8.876789 / 8.510780 s. Avoiding no-op argument copies, deferring keyword-text construction, skipping childless LINK_MAP scans, caching layout metadata with a 256-entry bound, and copying each tag's default-field template brought the final reference-host run to **7 passed, 1 deselected**: case_06 **8.411 / 8.843 s (4.9 % margin)**, software_a 11.6 %, all memory arms green (`coverage-perf-rtx-final.txt`). The graph now has **39 nodes** (+ `_record_layout_decode_metadata`). No threshold or expected reading changed.

## P13 test-oracle and golden consistency

Run 7 proves the intended CUBOID behavior: both `ASAM.C.CUBOID.ROW_DIR` and `ASAM.C.CUBOID.COLUMN_DIR` now have a complete record-layout span of 36 bytes (24 FNC_VALUES bytes plus axis components). Reverting P13 would violate the approved size rule. Add defect class **D8** for both tags: `length=None` at e07fb00 becomes 36. This makes **229 defect tags**, with **234,425 identical tags**. The reference oracle computes inline axis counts for the full `_CURVE_MAP_FAMILY`, and both golden entries take `class="D8"`, `length=36`. READ.49/2 adds a hand-written CUBOID reduction. `EXPECTED_SCANNED_TEST_FILES` becomes **276** after the new E5 test module and **277** after the coverage-completion module. These are intentional test/record updates, not a product rollback.

## Coverage findings accepted

- Correct the two AT matrix node ids to the real functions; their `full/covered/verified` status stands.
- Repair R-A2L-READ.51/1's unescaped pipe and malformed row without weakening the expected observable.
- The audit counts 27 missing and 109 partial requirement cases incorrectly marked full. These are test-coverage implementation gaps. Complete the named inputs/assertions through product routes; do not simply downgrade them to make the gate pass. Broad differential tests may prove a case only when they assert the case's exact observable.
- READ.52's protocol must use same-session base/current fresh-process medians and report pre-parse RSS and peak-minus-before, in addition to the existing bound checks.
- The audit's 162-shape premise is false: the enumerated families contain 160 shapes (31 + 40 + 47 + 4 + 20 + 9 + 9). H3e is separately excluded by the earlier CG-4 routing to Inc 3a, leaving 159 differential comparisons plus a current-behavior control. The records now state that scope explicitly.
- READ.4/5's all-line-20 premise is false for the declared MEAS fixtures: the CHARACTERISTIC address is on line 20 and the LENGTH/MATRIX_DIM arguments on line 23. READ.14/2 instead uses its documented standalone line-1 fixture. The mixed-line-end fixture must not turn CR followed by an empty line's LF into one CRLF.
- REF corrections are test-oracle corrections, not product rollbacks: duplicate BIT_MASK refusal, quoted positional tokens and unquoting, header-address source lines, and fail-closed invalid ECU_ADDRESS handling. The 160-shape differential is green with H3e routed to Inc 3a (`coverage-hostile-green.txt`).
- The final security review's LOW F1 is an oracle correction, not a product defect: REF unquoted a tag's own BYTE_ORDER argument and accepted quoted `"MSB_FIRST"` while the product correctly refused it. The new REF assertion first failed `16 is not None` (`ref-byte-order-red.txt`); REF now preserves the quoted token for normalization and diagnostics, and the focused case passes (`ref-byte-order-green.txt`). Product code was not changed for F1.
- The last security review leaves one LOW note open: a quoted positional MEASUREMENT datatype is accepted by the product but kept as no datatype by REF. P1 covers quoted numeric words, and the value is still bounded by the declared datatype table, so this is a permissiveness/oracle divergence with no memory-safety impact. It is documented for the backlog; no behavior change is made at E5. Its INFO notes (an unused join-block constant and TYPEDEF_AXIS span sizing outside scope) require no action.
- Every changed case must be re-audited after correction. The two real-app ATs remain full.

## Mutants and platform discipline

- Unit A ran its pytest arms on Windows, contrary to the batch rule. Its Windows transcripts are non-canonical supporting material only; the final mutation verdict must be re-run on the Linux runner after corrections. The final-suite Windows RED is not a product regression.
- **M10 is confirmed not realisable on the public route.** Universal-newline file opening normalizes CR/CRLF before `_lex_a2l_lines`, and the only other caller passes canonical lines. The Linux in-memory mutation changes private lexer output but leaves the public reading identical (`mutants-linux-A-M10-public-proof.txt`). It is recorded as `not realisable`, not a product failure or a required source change; the public READ.1 tests already prove the required behavior.
- Unit B must also be checked for platform compliance. Any Windows-run arms are repeated on Linux after corrections.

## Corrective order

1. Preserve reviews and this ruling; repair matrix ids/row shape.
2. Add the READ.70 design addendum and all product-finding RED tests.
3. Fix product only where RED proves the finding, with independent test corrections in disjoint ownership.
4. Complete the 27 missing and 109 partial cases and READ.52's protocol.
5. Re-run integration, code/security/coverage re-reviews and both mutant units on Linux.
6. Only then write `04-validation.md`, run `trace_check`, and prepare the merge.

No integrated product or test edit starts until mutant unit B has finished its baseline work.
