# Inc 1 — test cases (E4, independent tester)

Batch: 2026-11-01-batch-101 · base `e273181` · branch `b101-canon` · author: tester agent (not the implementer) · profile: `s19w/test-cases/TC-PROFILE.md` (TCP-ROW, TCP-DER, TCP-MAP).

Written from `01-requirements.md`, `02-graph.md` and `rulings.md` before the test file existed. One coverage item per row: every row of S0.3 is a single-behaviour `U` row, so each has one record, `/1` (TCP-ROW-1). The identifier of a case is allocated by the id registry later (TCP-ROW-4); until then the key is the identifier. The `ids` of each node are filled by tooling (TCP-MAP-8), not typed here.

Common to all cases: kind `process` (S0 documentation and process meta) · method `test` (TCP-STD-4) · level `unit` · technique: parse the repository's own files and compare with the row's threshold · node file `tests/test_requirements_canon.py` · plain pytest, standard library only, paths relative to the repository root.

## Coverage table

| Key | Row | Node (function in `tests/test_requirements_canon.py`) | asserts | Negative control |
|---|---|---|---|---|
| R-DOC-CANON.1/1 | `.1` | `test_canon_is_one_file_with_rows` | full | rename `REQUIREMENTS.md` |
| R-DOC-CANON.2/1 | `.2` | `test_canon_rows_have_id_form_sentence` | full | form `Shall`; a 4th cell |
| R-DOC-CANON.3/1 | `.3` | `test_canon_rows_open_with_their_form` | full | `When` row opening `The system shall` |
| R-DOC-CANON.4/1 | `.4` | `test_canon_rows_hold_the_obligation_word_once` | full | a row with two `shall` |
| R-DOC-CANON.5/1 | `.5` | `test_canon_row_ids_are_unique` | full | a copied row |
| R-DOC-CANON.6/1 | `.6` | `test_canon_modules_are_s0_to_s17_in_order` | full | two module headings swapped |
| R-DOC-CANON.7/1 | `.7` | `test_canon_history_is_the_committed_blob` | full | one byte of the history file changed |
| R-DOC-CANON.8/1 | `.8` | `test_canon_s0_table_cites_existing_rows` | full | `R-NOPE.1` in an absorbing cell; a parser that finds 0 ids |
| R-DOC-CANON.9/1 | `.9` | `test_review_files_hold_the_decisions` | partial | a review file removed; a module-table link broken |
| R-DOC-CANON.10/1 | `.10` | `test_review_files_name_only_existing_tests` | full | `test_does_not_exist` cited in a review file |
| R-DOC-CANON.11/1 | `.11` | `test_canon_rows_are_one_sentence` | partial | a row with two sentences |

Uncovered: none of the 11 rows. Limits are written per case under "Limit".

## Cases

### R-DOC-CANON.1/1
- **Row:** U — The system shall keep its requirements in one file, `REQUIREMENTS.md`, at the root of its repository.
- **Objective:** Verify that the requirements of the system are kept in one file, `REQUIREMENTS.md`, at the root of the repository, and that it holds requirement rows.
- **Class:** normal · boundary: the lower bound of 1 row.
- **Preconditions:** the repository tree at the commit under test, with `REQUIREMENTS.md` as committed (UTF-8; `\r\n` read as `\n`).
- **Inputs:** read `<root>/REQUIREMENTS.md` and parse its canon tables (N1, N2).
- **Expected result:** the file exists at the root and holds at least 1 row (1/1). A missing file fails the test naming the path.
- **Verified by:** `test_canon_is_one_file_with_rows` — asserts `full`: existence at the root and ≥ 1 parsed row, which is the row's threshold.
- **Negative control:** mutant — rename `REQUIREMENTS.md` → RED. On the base tree the old canon holds no strict table, so the case is also RED on `e273181`.
- **Limit:** a second file that also holds requirements is not detected; the threshold does not ask for it.

### R-DOC-CANON.2/1
- **Row:** U — The system shall give each requirement in `REQUIREMENTS.md` one table row with an id, a form and a sentence.
- **Objective:** Verify that every requirement row of `REQUIREMENTS.md` has exactly three cells: an id, a form and a sentence, each well formed.
- **Class:** normal · boundary: the id grammar with lower-case suffixes (`R-PARSE-001b`, `R-HEX-001a.1`).
- **Preconditions:** as `.1`; the canon holds at least the 2623 rows measured when the canon was built.
- **Inputs:** every line of every table whose header is exactly `| Id | Form | Requirement |`.
- **Expected result:** each row has 3 cells; the id matches `^R-[A-Za-z0-9.-]+$`; the form is one of `U`, `When`, `While`, `If`, `Where`; the sentence ends with `.`, `` .` `` or `.)` (2623/2623). A table with any other header is not a canon table.
- **Verified by:** `test_canon_rows_have_id_form_sentence` — asserts `full`.
- **Negative control:** mutant — form `Shall` on one row → RED; a 4th cell on one row → RED.
- **Limit:** the check cannot tell a sentence that ends well but is meaningless; `.3`, `.4` and `.11` judge the wording.

### R-DOC-CANON.3/1
- **Row:** U — The system shall write each requirement sentence in `REQUIREMENTS.md` in the form its row names, with the opening words of that form (CTX-CANON).
- **Objective:** Verify that each requirement sentence opens with the opening words of the form its row names.
- **Class:** normal · boundary: the five forms, including the discriminating `If … , then the system shall`.
- **Preconditions:** as `.2`; CTX-CANON fixes the opening words.
- **Inputs:** every canon row (form, sentence).
- **Expected result:** `U` → `^The system shall `; `When` → `^When .+?, the system shall `; `While` → `^While .+?, the system shall `; `If` → `^If .+?, then the system shall `; `Where` → `^Where .+?, the system shall ` (2623/2623). A row with an unknown form is left to `.2`, so a bad form fails one case only. A failure names the id and the line.
- **Verified by:** `test_canon_rows_open_with_their_form` — asserts `full`.
- **Negative control:** mutant — a `When` row whose sentence starts `The system shall` → RED.
- **Limit:** the content of the event, state or condition is not judged.

### R-DOC-CANON.4/1
- **Row:** U — The system shall write each requirement sentence in `REQUIREMENTS.md` with the obligation word of CTX-CANON exactly once.
- **Objective:** Verify that each requirement sentence holds the obligation word `shall` exactly once.
- **Class:** normal · boundary: 0 and 2 occurrences are both failures.
- **Preconditions:** as `.2`.
- **Inputs:** every canon row's sentence.
- **Expected result:** `len(re.findall(r"\bshall\b", sentence)) == 1` for 2623/2623 rows.
- **Verified by:** `test_canon_rows_hold_the_obligation_word_once` — asserts `full`.
- **Negative control:** mutant — a row with a second `shall` → RED.
- **Limit:** none beyond the word count.

### R-DOC-CANON.5/1
- **Row:** U — The system shall give each requirement row in `REQUIREMENTS.md` an id that no other row in the file uses.
- **Objective:** Verify that no requirement id is used by two rows.
- **Class:** normal.
- **Preconditions:** as `.2`.
- **Inputs:** the ids of all canon rows, with their line numbers.
- **Expected result:** 0 duplicates. A failure names the id and both lines.
- **Verified by:** `test_canon_row_ids_are_unique` — asserts `full`.
- **Negative control:** mutant — a copied row → RED.
- **Limit:** an id that differs only in case or by a lookalike character counts as a different id.

### R-DOC-CANON.6/1
- **Row:** U — The system shall group the requirement rows of `REQUIREMENTS.md` under the modules S0 … S17, in that order.
- **Objective:** Verify that the canon holds the modules S0 … S17, in that order, each with at least one row.
- **Class:** normal · boundary: the order, and the minimum of 1 row per module.
- **Preconditions:** as `.2`; a module starts at a line matching `^## (S\d+) · `.
- **Inputs:** the module headings and the rows under each.
- **Expected result:** exactly 18 headings, S0 … S17 in order; every module has ≥ 1 row.
- **Verified by:** `test_canon_modules_are_s0_to_s17_in_order` — asserts `full`.
- **Negative control:** mutant — two module headings swapped (S2 and S3) → RED.
- **Limit:** none.

### R-DOC-CANON.7/1
- **Row:** U — The system shall keep the requirements file that `REQUIREMENTS.md` replaced, byte for byte as committed at e273181, in `docs/requirements/history/`.
- **Objective:** Verify that the replaced requirements file is kept in `docs/requirements/history/` with exactly the bytes committed at `e273181`.
- **Class:** normal · boundary: one changed byte.
- **Preconditions:** the history file `docs/requirements/history/REQUIREMENTS-legacy-e273181.md` is checked out without line-ending conversion (`.gitattributes` `docs/requirements/history/** -text`, ruling R-6). The pinned value is the blob of `REQUIREMENTS.md` at `e273181`; the tester checked it with `git show e273181:REQUIREMENTS.md | sha256sum`.
- **Inputs:** the raw bytes of the history file (binary read, no normalisation).
- **Expected result:** sha256 = `4411f41b9a8d87ca6fb57e3740e6ac32fd6c8bbb320674404d0fd2e2b41b2899` on every platform. A missing file fails naming the path.
- **Verified by:** `test_canon_history_is_the_committed_blob` — asserts `full`.
- **Negative control:** mutant — one byte of the history file changed → RED. On the base tree the file does not exist, so the case is RED on `e273181`.
- **Limit:** the test cannot detect a wrong `.gitattributes` on its own; it detects the consequence (CRLF bytes) on the platform that runs it. The Windows-only consequence is not exercised on the Ubuntu CI.

### R-DOC-CANON.8/1
- **Row:** U — The system shall cite in the absorbing cell of each line of S0's table (S0.2) only ids of rows that exist in `REQUIREMENTS.md`.
- **Objective:** Verify that every row id cited in the absorbing cell of S0.2's lines is the id of a row that exists in the canon.
- **Class:** normal · boundary: abbreviations `.n` expanded from the last full id (`R-TUI-012.1, .7, .22`), an id with a letter and no dot (`R-PE-019a`), dash-numbered ids written in full (`R-SAVEDLG-16, R-SAVEDLG-24`).
- **Preconditions:** S0.2 runs from the heading `^#+ S0\.2\b` to `^#+ S0\.3\b`; its lines start with `| HLR-`; the absorbing cell is the second cell.
- **Inputs:** the second cell of every `| HLR-` line of that section; tokens: a full id `R-[A-Za-z0-9-]+(\.[0-9]+[a-z]?)*` (it sets the current stem); an abbreviation `\.\d+[a-z]?` right after a comma or `…`, expanded to `<stem>.<n>`.
- **Expected result:** at least 473 ids checked and 0 unresolved. A parser that finds fewer than 473 fails by the bound.
- **Verified by:** `test_canon_s0_table_cites_existing_rows` — asserts `full`.
- **Negative control:** mutant — `R-NOPE.1` in an absorbing cell → RED; mutant — every `| HLR-` line made unreadable to the parser (0 ids) → RED by the bound.
- **Limit:** an id written in a shape the token grammar does not know is not seen; the 473 bound guards the case of a parser that sees nothing, not one that sees less.

### R-DOC-CANON.9/1
- **Row:** U — The system shall keep, for each module, the decisions behind its rows in `docs/requirements/review/`.
- **Objective:** Verify that for each of the modules S0 … S17 a review file exists in `docs/requirements/review/`, holds a heading that names `Decisions`, and is linked from the canon's module table.
- **Class:** normal · boundary: 18 of 18 files.
- **Preconditions:** the review files are published under their review names `S<n>-ears-strict.md`; links in the canon have the form `](docs/requirements/review/<file>)`.
- **Inputs:** the 18 file names, the headings of each file, the links in the canon.
- **Expected result:** 18/18 files exist; each has a heading line (`#`…) containing `Decisions`; the canon links each of the 18 files and each link resolves.
- **Verified by:** `test_review_files_hold_the_decisions` — asserts `partial`: it proves the file, the heading and the link, not that every decision of the module is written in the file.
- **Negative control:** mutant — one review file removed → RED; mutant — one module-table link pointing at a missing file → RED.
- **Limit:** the completeness of each module's decisions is a review matter, not a test.

### R-DOC-CANON.10/1
- **Row:** U — The system shall name in `docs/requirements/review/` only tests that are defined under `tests/`.
- **Objective:** Verify that every test name written as a code span in the review files is the name of a test function or test class defined under `tests/`.
- **Class:** normal · boundary: spans naming files (`test_x.py`) and prefixes (ending `_`) are not test names and are skipped.
- **Preconditions:** the review files are the `.md` files of `docs/requirements/review/`; test definitions are the `def test_…` and `class Test…` of every `.py` under `tests/`.
- **Inputs:** every backticked span whose whole content matches `^test_\w+$` (not ending `_`), against the set of defined names.
- **Expected result:** 0 missing, with at least 1000 names checked (about 1 109 when the canon was built). A failure names each missing name with its file.
- **Verified by:** `test_review_files_name_only_existing_tests` — asserts `full`.
- **Negative control:** mutant — `test_does_not_exist` cited in a review file → RED.
- **Limit:** the check proves the name is defined, not that the test still checks what the review says; this is the phantom-name check that G4 gave and ruling R-3 retired.

### R-DOC-CANON.11/1
- **Row:** U — The system shall write each requirement sentence in `REQUIREMENTS.md` as one sentence.
- **Objective:** Verify that no requirement sentence holds a second sentence.
- **Class:** normal · boundary: a code span containing a full stop and a capital is not a sentence break.
- **Preconditions:** as `.2`.
- **Inputs:** every canon row's sentence with its code spans removed.
- **Expected result:** `re.search(r"\. [A-Z]", …)` finds nothing in 2623/2623 rows.
- **Verified by:** `test_canon_rows_are_one_sentence` — asserts `partial`: it detects the break signature (full stop, space, capital) and not a second sentence that starts with a lower-case letter, a digit or a code span.
- **Negative control:** mutant — a row with a second sentence (`… end. Then …`) → RED.
- **Limit:** as above.

## Evidence (state: `executed`; nothing here is `approved`: the judgement is the reviewers')

Test file: `tests/test_requirements_canon.py` (sha256 `79d654e4…0590`, 11 tests, no AT/TC id in any name). Python 3.11.15, pytest 8.4.2, Windows 11. Every run below is one complete run; each transcript is written by `tee` in `.dev-flow/2026-11-01-batch-101/inc-1/evidence/` and starts with its own command line.

| Run | Tree | Command (abridged) | Result | Transcript |
|---|---|---|---|---|
| RED on base | `s19_app-b101-base` detached at `e273181` (old canon); the test file copied in, then deleted; `git status --porcelain` empty afterwards | `pytest -q -p no:cacheprovider --tb=line tests/test_requirements_canon.py` | 11 failed in 0.30 s | `evidence/red-base.txt` |
| GREEN on the new canon | scratch mirror: `s19w/canon/REQUIREMENTS.md` (sha256 `0709ab3f…8e99`), the history file from `git show e273181:REQUIREMENTS.md` (sha256 `4411f41b…2899`), the 18 `S*-ears-strict.md`, a copy of the worktree `tests/` (239 `.py`) | `pytest -q -p no:cacheprovider --rootdir <mirror> tests/test_requirements_canon.py` (after a `--collect-only` that lists the 11 nodes) | 11 passed in 0.30 s | `evidence/green-mirror.txt` |
| Negative controls | 18 mutants, each on a fresh copy of the mirror | same command with `--tb=short` | 18/18 RED, the target test RED in every one (table below) | `evidence/mutants.txt` |

Why each RED on base is behavioural, not a crash: the old canon has no `| Id | Form | Requirement |` table (0 rows, so `.1` fails its "≥ 1 row" bound and `.2`–`.5`, `.11` fail the 2623-row floor with the parse count in the message), no `## S<n> · ` heading (`.6` reads `[]`), no history file (`.7`), no `S0.2`/`S0.3` headings (`.8`), no review files (`.9`: 36 offences; `.10`: 0 of the 1000 bound). No test fails with a traceback from the parser. None of the 11 is "cannot be RED on base".

Facts measured on the new canon with the shared parser (they match the graph's probe):

- 2623 rows, all with 3 cells; forms U 392, When 993, While 143, If 1095; modules S0 … S17 in order.
- S0.2: 473 ids checked, 0 unresolved, of which 151 are `.n` abbreviations expanded from the full id before them.
- Review files: 1 109 distinct `test_…` names cited, 0 missing in the 239 test files of the mirror.
- The pinned hash is the blob of `REQUIREMENTS.md` at `e273181`: `git show e273181:REQUIREMENTS.md | sha256sum` = `4411f41b…2899`; its git blob id is `87ce9f9d456f138a4e1e42373fee0332d132b82a`.

### Mutant table (negative controls)

"Only the target" means the other 10 tests stayed GREEN in that run.

| Mutant | Row | Mutation (on a copy of the mirror) | Result |
|---|---|---|---|
| M1 | .1 | rename `REQUIREMENTS.md` | RED: target, and 8 more that read the canon (`.7` and `.10` do not, and stay GREEN) |
| M2a | .2 | `R-DOC-README.1` form `U` → `Shall` | RED: only the target (`.3` skips an unknown form, so one fault shows once) |
| M2b | .2 | a 4th cell on `R-DOC-README.1` | RED: only the target |
| M3 | .3 | `R-DOC-README.1` filed as `When`, sentence still opens `The system shall` | RED: only the target |
| M4 | .4 | a second `shall` in `R-DOC-README.1` | RED: only the target |
| M5 | .5 | `R-DOC-README.1` copied below itself | RED: only the target |
| M6 | .6 | headings of S2 and S3 swapped | RED: only the target |
| M7 | .7 | one byte of the history file flipped (offset 100) | RED: only the target |
| M7b | .7 | the history file with CRLF line endings | RED: only the target; the message names `.gitattributes … -text` |
| M8a | .8 | `R-NOPE.1` in the absorbing cell of HLR-001 | RED: only the target (1 of 474 unresolved) |
| M8b | .8 | `R-TUI-052.1 … .3` → `… .99` in HLR-008 (an abbreviation) | RED: only the target; proves the `.n` expansion is live |
| M8c | .8 | every `\| HLR-` line of S0.2 unreadable (104 lines, 0 ids) | RED: only the target, by the bound of 473 |
| M9a | .9 | `S7-ears-strict.md` removed | RED: only the target |
| M9b | .9 | the S7 module-table link points at a missing file | RED: only the target |
| M9c | .9 | the `Decisions` heading of the S5 file renamed | RED: only the target |
| M10 | .10 | `test_does_not_exist` cited in `S2-ears-strict.md` | RED: only the target (1 of 1 110) |
| M11 | .11 | `R-DOC-README.1` with a second sentence | RED: only the target |
| M12 | floor | canon cut to 3 rows (a blind parser) | RED: `.2`, `.3`, `.4`, `.5`, `.6`, `.8`, `.11` (`.1` stays GREEN by its bound of 1 row; `.7`, `.9`, `.10` do not read the rows) |

## Deviations from the graph (none changes a row's threshold)

1. **N2 needs an escaped-pipe rule.** 9 canon lines hold `\|` inside the sentence; splitting on every `|` would give them more than 3 cells and fail `.2` on the real canon. The parser splits on a pipe not preceded by a backslash. The graph does not state this; the contract is otherwise right.
2. **Floors.** The row thresholds `2623/2623` are exact counts of a canon that later increments extend, so the guard asserts `len(rows) >= 2623` (`MIN_ROWS`) and then checks every row. Reason: with no floor `.3`–`.5` and `.11` pass on a parser that finds 0 rows. A ruling that retires rows lowers the floor in the same change. `.10` uses a bound of 1000 distinct names (1 109 measured).
3. **N13 counts distinct names**, as the row's "~1 109" does (occurrences are 1 410).
4. **N12 is stricter than its sentence** in one way: it requires each of the 18 files to be linked from the canon (a removed link goes RED), not only that each present link resolves.
5. **Scope of `.10`:** all `*.md` in `docs/requirements/review/` (the row says "in `docs/requirements/review/`"), so `CODE-CHANGES.md`, `RECONCILE-570b4b5.md` and `README.md` are read too. The mirror holds only the 18 `S*-ears-strict.md`; a read-only run of the test in the implementer's worktree (in flight, 21 files in the review folder, canon and review files byte-identical to the mirror's) gave 11 passed. That run is not part of the evidence set above.

## Gaps and limits

- Uncovered requirements: none of R-DOC-CANON.1 … .11.
- Not covered by these tests: the registry-guard changes N15–N20 (G4 retirement, `EXPECTED_SCANNED_TEST_FILES`, AT-286, TC-497, `tools/counterfactual_id_registry.py`, the registry JSONL). They belong to the existing registry tests; the tester did not run `tests/test_id_registry.py` (the mirror has no `tools/` or registry file).
- Platform: all runs on Windows 11 only. The Ubuntu CI is not run here; `.8`, `.9` and `.10` read UTF-8 with an explicit decode and use forward-slash relative paths, and `.7` reads raw bytes, so a difference is not expected, but it is unobserved. The Windows-only CRLF hazard of `.7` is exercised by M7b.
- The mirror is not the final worktree: the GREEN transcript proves the guard on the inputs the implementer is told to build (`s19w/canon`, `e273181` blob, the 18 review files); the orchestrator's gate run on the committed tree is the run that counts.
- `.9` and `.11` are `partial` (see their cases); the others are `full` against the approved thresholds.
- The suite as a whole (`pytest -q` for the project) was not run: it is the orchestrator's gate run (C-25).

## Evidence checklist

- [x] Every test named exists on disk at `tests/test_requirements_canon.py`: the 11 functions of the coverage table (`--collect-only` listing at the head of `evidence/green-mirror.txt`).
- [x] Each result read from one complete run's own output, command quoted at the head of each transcript.
- [x] RED-on-base captured: base `e273181`, `evidence/red-base.txt`, 11 failed, copy removed, base clean.
- [x] Each test asserts an observable outcome (file content, hash, link target, defined names), not a call sequence.
- [x] Uncovered requirements named: none; limits named above.
- [x] Environment limits declared above.
- [x] No real PII, credentials or client data: the fixtures are the repository's own text files.
- [x] Evidence states used: `executed`, `planned` (nowhere left), `n/a`; `approved` is not written.
