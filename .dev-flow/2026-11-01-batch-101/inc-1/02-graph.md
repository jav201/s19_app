# Inc 1 — prototype graph (E2, corrected after E3 round 1)

The slice has no product function. The graph covers the new guard `tests/test_requirements_canon.py` and the registry-guard changes of ruling R-3. Contracts and examples come from the rows of `01-requirements.md`; no code was written before this graph.

## The canon guard

| # | Node | In | Out | Contract | Examples |
|---|---|---|---|---|---|
| N1 | `canon_text()` | — | `str` | reads `REQUIREMENTS.md` at the repo root as UTF-8, `\r\n` normalised to `\n` | missing file → the test fails naming the path |
| N2 | `parse_canon(text)` | `str` | `Canon(rows, modules)` | a **row** is a line inside a table whose header is exactly `\| Id \| Form \| Requirement \|`: `Row(id, form, sentence, module, line)`; a **module** starts at `^## (S\d+) · `; a table with any other header is not a canon table | `\| R-READ-001.1 \| When \| When …, the system shall … . \|` under `## S1 · …` → `Row("R-READ-001.1", "When", "When …", "S1", n)`; `\| Id \| Form \| Requirement \| Code today \|` → not a canon table |
| N3 | `OPENING[form]` | form | regex | `U` `^The system shall `; `When` `^When .+?, the system shall `; `While` `^While .+?, the system shall `; `If` `^If .+?, then the system shall `; `Where` `^Where .+?, the system shall ` | `("If", "If the file is empty, then the system shall …")` → match; `("When", "The system shall …")` → no match |
| N4 | test .1 `test_canon_is_one_file_with_rows` | Canon | pass/fail | `REQUIREMENTS.md` exists at the root; ≥ 1 row | renamed file → fail |
| N5 | test .2 `test_canon_rows_have_id_form_sentence` | Canon | pass/fail | each row: id `^R-[A-Za-z0-9.-]+$`; form ∈ {U, When, While, If, Where}; sentence ends `.`, `` .` `` or `.)` | `R-PARSE-001b`, `R-HEX-001a.1` → pass; form `Shall` → fail |
| N6 | test .3 `test_canon_rows_open_with_their_form` | Canon | pass/fail | `OPENING[row.form]` matches | a `When` row starting `The system shall` → fail naming id and line |
| N7 | test .4 `test_canon_rows_hold_the_obligation_word_once` | Canon | pass/fail | exactly one `\bshall\b` | two → fail |
| N8 | test .5 `test_canon_row_ids_are_unique` | Canon | pass/fail | no id twice | copied row → fail naming both lines |
| N9 | test .6 `test_canon_modules_are_s0_to_s17_in_order` | Canon | pass/fail | module ids are exactly S0 … S17 in order; each has ≥ 1 row | S3 before S2 → fail |
| N10 | test .7 `test_canon_history_is_the_committed_blob` | `docs/requirements/history/REQUIREMENTS-legacy-e273181.md` | pass/fail | sha256 of the raw bytes == `4411f41b9a8d87ca6fb57e3740e6ac32fd6c8bbb320674404d0fd2e2b41b2899` | one byte changed → fail; a CRLF checkout is prevented by `.gitattributes` `-text` |
| N11 | test .8 `test_canon_s0_table_cites_existing_rows` | Canon text | pass/fail | section from `^#+ S0\.2\b` to `^#+ S0\.3\b`; for each line starting `\| HLR-`, the second cell; tokens: a full id `R-[A-Za-z0-9-]+(\.[0-9]+[a-z]?)*` sets the current stem; an abbreviation `\.\d+[a-z]?` right after a comma/`…` expands to `<stem of the last full id>.<n>`; every token resolves to a row id; the number of tokens checked is ≥ 473 | `R-TUI-012.1, .7, .22` → `R-TUI-012.1`, `R-TUI-012.7`, `R-TUI-012.22`; `R-PE-019a` → itself; `R-SAVEDLG-16, R-SAVEDLG-24` → both (S0 writes dash-numbered ids in full; an abbreviation is used only after a dotted id); `R-NOPE.1` → fail; a parser that sees 0 tokens → fail by the bound. Probe on the canon: 473 checked, 0 unresolved |
| N12 | test .9 `test_review_files_hold_the_decisions` | `docs/requirements/review/`, canon module table | pass/fail | `S0-ears-strict.md` … `S17-ears-strict.md` exist, each with a heading containing `Decisions`; every link `](docs/requirements/review/<file>)` in the canon resolves | one file missing → fail |
| N13 | test .10 `test_review_files_name_only_existing_tests` | review files, `tests/**/*.py` | pass/fail | every code span whose whole content matches `^test_\w+$` in the review files is the name of a `def test_…` or `class Test…` in `tests/`; spans naming files (`test_x.py`) or prefixes (ending `_`) do not match and are skipped | `test_does_not_exist` → fail |
| N14 | test .11 `test_canon_rows_are_one_sentence` | Canon | pass/fail | after removing code spans, no `\. [A-Z]` in the sentence | `… end. Then …` → fail |

## Registry-guard changes (ruling R-3, R-2, R-7)

| # | Change | Contract after the change | Example |
|---|---|---|---|
| N15 | `tests/test_id_registry.py`: remove `g4_requirement_citations_are_live`, its rule test (TC-603), AT-281's G4 arm, TC-609's anchor assertion, `MAX_EXEMPT_ANCHORS` | AT-281 still proves G1–G3, G5–G7 can each be made to fail; TC-609 still checks entries | the G4 arm is gone; the other arms unchanged |
| N16 | `tests/test_id_registry.py` `EXPECTED_SCANNED_TEST_FILES` | equals the measured `len(scanned_test_files())` with the new file | 238 on base + 1 = 239 |
| N17 | `tests/test_batch91_registry_hygiene.py` | the census node removed; AT-286 keeps its two other nodes | — |
| N18 | `tests/test_report_addendum_bound.py` | TC-497's node removed (its helpers removed only if no other caller) | — |
| N20 | `tools/counterfactual_id_registry.py` | its G4 arm and its import of `g4_requirement_citations_are_live` removed; the tool still runs the other arms | — |
| N19 | `AT-TC-REGISTRY.jsonl` | TC-603, TC-497 → `RETIRED` with `retired_reason`; AT-286 statement and nodes without the census; `_meta.g4_exempt_anchors` removed | the registry tests (TC-609 and others) stay green |

## Interfaces

None shared with other increments. Inc 2+ (defect increments) add or change rows in `REQUIREMENTS.md`; N4–N14 then check them. The test-case increment adds the records' guard.
