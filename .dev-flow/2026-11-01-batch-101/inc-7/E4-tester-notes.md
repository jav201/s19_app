# Inc 7 - E4 tester notes (independent tester)

Written from the approved design only (requirements, test cases, graph examples, E1/E3 rulings). No implementation source was read; no test was run against the in-progress tree. Base for RED: `9f9f6af` (merge-base of HEAD and main; the records say `e266395`, the real merge-base already holds Inc 2).

## Files touched (tests and goldens only, no source)

- New tests appended to `tests/test_diff_report_service.py` (about 28 functions) and `tests/test_before_after_report.py` (17 functions); no new test file (D-8).
- `tests/test_report_field_census.py`: Mode-B-in-a-cell AST guard extended to `diff_report_service.py` (and `_md_path`), checker factored into `_mode_b_cell_offenders`, plus a counterfactual test `test_mode_b_cell_guard_flags_a_planted_cell`.
- Re-pinned (function names unchanged): the 18 nodes of E1-slice section 4, plus `test_at_056a_dropdown_selection_filters_both_triggers` (orchestrator addendum: Markdown header now `only-first\.json`, HTML keeps the literal). Not re-pinned, as instructed: `test_at_056e_a2b_diff_report_byte_identical_despite_selection`.
- Goldens `tests/goldens/batch35/at054b-before-after-report.{md,html}`: title and the two escaped labels only.
- Every negative on a file-derived name checks both spellings (raw and escaped).

## Test to case mapping

Real ids are in the Tests column of `02-test-cases.md` (45 rows updated). "Full" is claimed only where the shipped surface or generator produces what the test asserts. Partial: R-CMP-004.1/1 (also the filtered-header node), R-CMP-004.5/1, R-CMP-004.9.1/5 (TC-717 re-pin), R-CMP-004.14/6, R-CMP-003.2/2 (golden lines), R-BEFORE-AFTER-REPORT-001.24/4 (existing TC-311 node, unchanged, stays GREEN).

## Cases not expressible, or weaker than written

- R-CMP-005.16/1-2 inject the failure by wrapping `builtins.open` / `io.open` for the report file name (half the payload, then `OSError`). The test asserts the injection was hit, so an implementation that writes through `os.open` / `os.fdopen` fails loudly instead of passing vacuously.
- R-CMP-005.16 sub-case N-1 assumes the temporary name is exactly `<final name>.part` (the CTX-DIFFREPORT `file write` term).
- A-6 (4 MiB worst-case timing and RSS) and A-8 on the implemented tree: `not-run`. A-8 grep on base: no in-place mutation of `mac_records`, `_a2l_enriched_tags` or `current_a2l_data`. A-7: goldens and the new tests hold no home folder (grep clean).
- R-CMP-004.9.1/9 (flow-A2B one escape) rests on existing nodes; they are guards and are GREEN on base by design.
- Reader-level census (9.1/11) uses markdown-it with links and HTML on; the planted payload is checked against the same reader as a control so the check can fail.

## RED on base (`evidence/inc-7/red-01-tester-base.txt`)

64 nodes run (45 new incl. 2 census, 19 re-pinned): 54 failed, 10 passed.

Behavioural reasons: 512-row cap and cap lines (14/1-5); partial `.md` / `.html` left (5.16/1-2, 4); no `.part` exclusivity (5.16/3 DID NOT RAISE); orphan `.md` (5.17/1-2); raw labels, symbols, paths, filter name and refusal message (9.1/x, 9.2/x, 15/x, 21/2: live `html_inline` and `link_open` tokens in 9.1/11); `# Diff report` title (32-34); `a2l=absent` / `Symbols -` through key `b` (35/2, 24/3, 003.2/1); `(screen 7)` reason (11/1, 11/2).
Three composer tests (35/1, 24/1, 24/2) fail on base with `TypeError: unexpected keyword argument` (the composer cannot be given the loaded A2L at all): an interface RED, not an output diff.

GREEN on base by design (guards, cannot be RED): R-CMP-004.1/1 and /2, R-CMP-004.5/1, R-CMP-004.8/1, R-CMP-003.2/2, R-CMP-004.9.2/4, R-CMP-004.14/7 (differential oracle; kills M19-type mutants), the two census AST tests, and `test_tc312_zero_match_notice_and_refusal_disjoint` (only its negatives were re-pinned to both spellings).

GREEN on the implemented tree: `not-run` by me (not allowed to read or run it); the orchestrator's gate run owns it.

## Ambiguities (not resolved by reading the code)

1. Records name base `e266395`; the merge-base of HEAD and main is `9f9f6af`.
2. R-CMP-004.14/2 says HTML and Markdown row counts "equal per window"; the HTML pane shows an unmapped ASCII cell as a space (F-E3-5), so the test compares counts and addresses, not row text.
3. 9.1/11 spec lists a leading `1) ` and `- ` in the payload; all emission sites have a literal prefix, so those are interior in the document. Kept as written.
4. Order of names in a shared Symbols cell (A2L first, then MAC) is taken from case .24/2 text.
5. Waits: `app.workers.wait_for_complete()` (existing idiom in these files) and `wait_until` for the A2B status; no bare pause counted.
