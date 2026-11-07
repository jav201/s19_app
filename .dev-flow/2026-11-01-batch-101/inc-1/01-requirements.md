# Inc 1 — the strict-EARS requirements canon · requirements (E1, corrected after E3 round 1)

Batch: 2026-11-01-batch-101 · base `e273181` · branch `b101-canon` · flow: dev-flow-v3-beta (operator ruling 2026-11-01: the canon swap is Inc 1, split from the test-case records, which come in a later increment of this batch).

## User story

### US-101.1 — As the engineer who changes s19_app, I read and change one requirements file in which every requirement is a single strict EARS sentence with a stable id, so that each requirement can be tested on its own and traced to its tests.

Source: the strict EARS review of the 18 requirement modules (S0 … S17), accepted by the operator on 2026-10-30, reconciled with batch-100 at `570b4b5` and delta-checked to `e279c8b` on 2026-11-01 (no product code changed between `e279c8b` and `e273181`).

## Scope

- `REQUIREMENTS.md` is replaced by the normative part of the review: the reading rules (E1–E7), a module table (module, name, rationale link), and per module its context notes and its rows `| Id | Form | Requirement |`: 2623 rows (2612 product rows and the 11 rows below).
- The replaced file moves, as committed at `e273181`, to `docs/requirements/history/REQUIREMENTS-legacy-e273181.md` (git rename; `.gitattributes` marks the folder `-text`, ruling R-6).
- The review files are published as rationale in `docs/requirements/review/` with their review names (`S<n>-ears-strict.md`), with `CODE-CHANGES.md`, `RECONCILE-570b4b5.md` and a README (their "Code today" column is a snapshot as of `e273181`).
- New guard `tests/test_requirements_canon.py` checks the rows below.
- Registry guards adapted to the new canon (ruling R-3): G4 retired with TC-603; AT-281's G4 arm, TC-609's anchor check and `g4_exempt_anchors` removed; AT-286's census of declared ids removed (AT-286 keeps its two other nodes). TC-497 retired (ruling R-2). `EXPECTED_SCANNED_TEST_FILES` set to the measured count (ruling R-7).
- Docs that describe the old format are corrected (`CLAUDE.md`, `README.md`, `docs/README.md`, `docs/architecture.md`, `docs/overview.md`, `docs/engineering-rules.md`); the failure message of `tests/test_tui_patch_json.py:1016` is re-pointed (ruling R-4).
- Out: no product source changes; the test-case records and their status document (later increment); code comments and other docs that cite sections of the earlier canon (ruling R-4).

## Requirements (module S0, section S0.3; id prefix R-DOC-CANON; all US-101.1)

| Id | US | Form | Requirement | Pass threshold | Negative control |
|---|---|---|---|---|---|
| R-DOC-CANON.1 | US-101.1 | U | The system shall keep its requirements in one file, `REQUIREMENTS.md`, at the root of its repository. | the file exists and holds ≥ 1 row (1/1) | rename the file → RED |
| R-DOC-CANON.2 | US-101.1 | U | The system shall give each requirement in `REQUIREMENTS.md` one table row with an id, a form and a sentence. | every row of every `\| Id \| Form \| Requirement \|` table has 3 cells, id matches `^R-[A-Za-z0-9.-]+$`, form in the five, sentence ends with `.`, `` .` `` or `.)` (2623/2623) | form `Shall` or a 4th cell → RED |
| R-DOC-CANON.3 | US-101.1 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` in the form its row names, with the opening words of that form (CTX-CANON). | 2623/2623 | a `When` row starting `The system shall` → RED |
| R-DOC-CANON.4 | US-101.1 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` with the obligation word of CTX-CANON exactly once. | 2623/2623 have one `\bshall\b` | a row with two → RED |
| R-DOC-CANON.5 | US-101.1 | U | The system shall give each requirement row in `REQUIREMENTS.md` an id that no other row in the file uses. | 0 duplicates | copy a row → RED |
| R-DOC-CANON.6 | US-101.1 | U | The system shall group the requirement rows of `REQUIREMENTS.md` under the modules S0 … S17, in that order. | 18 `## S<n> ·` headings in order, each with ≥ 1 row | swap two module headings → RED |
| R-DOC-CANON.7 | US-101.1 | U | The system shall keep the requirements file that `REQUIREMENTS.md` replaced, byte for byte as committed at e273181, in `docs/requirements/history/`. | sha256 of the file's bytes = `4411f41b9a8d87ca6fb57e3740e6ac32fd6c8bbb320674404d0fd2e2b41b2899` (the blob of `REQUIREMENTS.md` at `e273181`) on every platform | change one byte → RED |
| R-DOC-CANON.8 | US-101.1 | U | The system shall cite in the absorbing cell of each line of S0's table (S0.2) only ids of rows that exist in `REQUIREMENTS.md`. | ≥ 473 ids checked (full ids and `.n` abbreviations expanded from the full id before them), 0 unresolved | `R-NOPE.1` in an absorbing cell → RED; a parser that finds 0 ids → RED by the ≥ 473 bound |
| R-DOC-CANON.9 | US-101.1 | U | The system shall keep, for each module, the decisions behind its rows in `docs/requirements/review/`. | 18/18 review files exist, each with a heading naming `Decisions`, and each module-table link resolves | remove one file or break one link → RED |
| R-DOC-CANON.10 | US-101.1 | U | The system shall name in `docs/requirements/review/` only tests that are defined under `tests/`. | every backticked `test_…` name in the review files is a `def test_…` (or `class Test…`) under `tests/` (0 missing of ~1 109) | cite `test_does_not_exist` → RED |
| R-DOC-CANON.11 | US-101.1 | U | The system shall write each requirement sentence in `REQUIREMENTS.md` as one sentence. | 2623/2623: no `. [A-Z]` outside code spans | a row with two sentences → RED |

Context note CTX-CANON (forms, opening words, obligation word, one sentence) is in S0's context notes.

## Slice

No product function changes. Test and data changes:
- `tests/test_requirements_canon.py` (NEW): one test per row above (11), one shared row parser.
- `tests/test_id_registry.py`: G4 (`g4_requirement_citations_are_live`), its rule test (TC-603), AT-281's G4 arm, TC-609's anchor assertion and `MAX_EXEMPT_ANCHORS` removed; `EXPECTED_SCANNED_TEST_FILES` measured.
- `tests/test_batch91_registry_hygiene.py`: `test_at286_no_declared_id_is_absent_from_the_registry` removed.
- `tests/test_report_addendum_bound.py`: `test_tc497_shipped_requirement_carries_the_residuals_with_their_numbers` removed with its helpers if unused elsewhere.
- `tests/test_tui_patch_json.py`: one failure-message string.
- `AT-TC-REGISTRY.jsonl`: TC-603 and TC-497 RETIRED with reasons; AT-286 statement and nodes without the census; `g4_exempt_anchors` removed from `_meta`.
- `.gitattributes`: `docs/requirements/history/** -text`.
