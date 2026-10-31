# E4 — integration notes (batch-100 Inc 8a)

Author: software-dev agent (E4 integration). Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc8a`, branch `b100-inc8a`, base `dc3b314`. Nothing committed. Source edits only in `variant_execution_service.py` and `project_gather_service.py` (`app.py` and `manifest_writer.py` unchanged by integration); `workspace.py` and `prototypes/` untouched. CRLF kept in every touched file (checked after each edit).

## 1. Orchestrator rulings applied

| # | Ruling | File | What changed |
|---|---|---|---|
| 1 | G-1 / D-B5: the painted next step follows the active document's reason | `variant_execution_service.py` | New table `_NOT_READABLE_NEXT_STEP_BY_REASON` (`too large to reopen` → `open it from the Patch Editor (it can take a while)`; `could not be read` → `check that the file can be opened, then Load again`) and `_next_step(problem)`, used by `compose_load_announcement` instead of `PROBLEM_NEXT_STEP[kind]`. Any other `not readable` reason (link, unreadable, an image) keeps the kind's token `replace the file, or Save project to drop it`. The two reason strings occur only for the active document (the app's `_DOCUMENT_REASON` and the writer's D-B5 branch), checked with grep. |
| 2 | Merge row only when the target holds `project.json` | `project_gather_service.py` | `plan_project_save`: `project.json` row is `new` when the target has no `project.json` (lexists), else `merge` for a merge target, else `rewrite`. Docstring Data Flow line updated. `test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload` passes unchanged (no re-pin needed). |
| 3 | A refused `active_document` (incl. a link) at Load = exactly one `not readable` problem on the document's text, 0 `manifest damaged` rows | `variant_execution_service.py` | (a) `manifest_problems`: an issue carrying the `_ISSUE_KEY = active_document` mark becomes `ProjectFileProblem("not readable", <entry text>, <reason>)` instead of `manifest damaged`. (b) `_parse_manifest_active_document`: a walk refusal for a link rewords its reason mark from "a file path goes through a link or junction" to "the file is a link and is not opened" (the reopen's wording, `_DOCUMENT_REASON[link]` in `app.py`); new constants `_REASON_LINK`, `_REASON_DOCUMENT_LINK` (the two walk sites now use `_REASON_LINK`, same text). Out-of-form / escape refusals keep the reader's reason (`_ISSUE_REASON` mark or `_MANIFEST_REASON[code]`). (c) `read_project_manifest` passes the refused raw text to `_parse_manifest_files` → `_recorded_file(..., refused_document=)`: a `files` key equal to the refused document that is OUT of the O-2 scope is skipped with no finding of its own, so the document stays one problem. A key IN scope is read as usual (first attempt skipped it unconditionally; `active_document: "firmware.s19"` then lost the image's own record and painted `no digests saved` — caught by the tc_30 node, fixed with the new helper `_top_level_recorded`, which the scope test in `_recorded_file` now also uses). `check_project_files` and the reopen needed no change: the check takes its manifest rows from `manifest_problems`, and the reopen is not called for a refused value (`manifest.active_document is None`). |
| 4 | Re-pins accepted | tests | See §3. |
| 5 | Remaining failures | — | tc_29 second-save: passed alone 3 of 3 (7.7–8.1 s) on the integrated tree before any integration source edit; no production or test fix made. The panel-add helper repair the tester made before RED is what fixed it. In the GREEN run: see §5. |
| 6 | Gaps R-08, R-32, R-33, `classify_active_document` direct | tests | See §4. R-12 stays a named gap. |

## 2. Fixes by file

- `s19_app/tui/services/variant_execution_service.py` — rulings 1 and 3 (above). Why: G-1 (two `not readable` rows painted a next step Save project does not perform, R8 refined keeps them); ruling 3 (the reader's link refusal and the app's link outcome painted two different kinds for one file, and the refused document's `files` key added a second `manifest damaged` row).
- `s19_app/tui/services/project_gather_service.py` — ruling 2 (the plan said `merge` for a `project.json` the save creates; LLR-167.6 plan = written tree).
- `s19_app/tui/app.py`, `s19_app/tui/services/manifest_writer.py` — no integration edit.

## 3. Re-pins (old → new → requirement)

| # | Node | Old | New | Requirement |
|---|---|---|---|---|
| RP-2 | `test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` | 7 placement calls | 8; plus: exactly one placement call inside `_write_editor_document`, and it passes `workarea_root` | LLR-170.2 / E3 R1 (the pasted document is written through the one placement), LLR-171.4 / SEC-1 |
| RP-3 | `test_b100_save_image.py::test_tc_b100_15_patched_s19_is_emitted` | project top-level = `firmware.s19`, `project.json` | project files (recursive) = `firmware.s19`, `patches/changes.json`, `project.json` | LLR-170.2 |
| RP-4 | `test_b100_save_image.py::test_tc_b100_59_gather_service_imports_no_change_module` | exact import set without `stat` | set + stdlib `stat`; plus an explicit assertion that no imported module name contains "change" (the stated intent) | E3 R11 / S3R2-5 (one `lstat` mode check) |
| RP-5 | `test_b100_save_image.py::test_tc_b100_59_pending_patch_in_the_open_project` | rows image / mac / manifest | rows image / mac / document `changes.json` `new` / manifest | LLR-167.6 Inc 8a arm, LLR-170.2 |
| — | `test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload` | — | not re-pinned: passes after ruling 2 | LLR-167.6 |
| RP-I2 | `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` | `EXPECTED_SCANNED_TEST_FILES = 224` | 225, with the history line "batch-100 Inc-8a: 224 -> 225 (tests/test_b100_document.py)" — the guard's own instruction for a legitimate new module | house rule of the guard (same bump every increment made) |
| RP-I1 | `test_b100_document.py::test_tc_b100_30_refused_record_is_one_manifest_damaged_row_and_no_reopen` | renamed `..._is_one_not_readable_row_and_no_reopen`; problems = `["manifest damaged"]` | problems = `[("not readable", "firmware.s19")]` | ruling 3 (supersedes the `proto-8a-app.md` example "HLR-170 invalid arm … 1 manifest damaged row") |

## 4. Gaps filled (new nodes)

| Gap | Node(s) | What it asserts | Mutant that turns it RED (run, `evidence/inc-8a/mutants-integration-01.txt`) |
|---|---|---|---|
| ruling 1 | `test_b100_document.py::test_tc_b100_30_not_readable_document_paints_the_next_step_of_its_reason[too_large|io_error|link|unreadable]` | pure composer: reason → painted detail `reason - next step` | M-I4 next step by kind only → 2 failed (too_large, io_error); link / unreadable hold by design |
| ruling 3 (tester's open question) | `test_b100_document.py::test_tc_b100_30_linked_document_is_one_not_readable_row[recorded|unrecorded]` | Load of a P whose `patches/boost.json` is a symlink → exactly `[("not readable", "patches/boost.json", "the file is a link and is not opened - replace the file, or Save project to drop it")]`, 0 entries, image opens | M-I5 (refused `files` key not skipped) → RED on `[recorded]`; M-I6 (refused document stays `manifest damaged`) → 3 RED |
| R-08 (drop on `link` at Save) | `test_b100_save_guards.py::test_tc_b100_05_r8_target_document_that_is_a_link_is_not_carried` | merge into `ab` whose document is a symlink → no `active_document` written, 1 line naming it in user terms, the private target unchanged. The reader refuses the link at its walk, so this is the R5 path (`project.json.previous-*` kept) | (end-to-end; the carry is decided by the reader) |
| R-08, classifier branch | `test_b100_save_guards.py::test_tc_b100_05_r8_document_turned_into_a_link_before_the_check_is_dropped` | the file is swapped for a symlink after the read and before Save project's classification (a wrapper around the real `recorded_document_state`) → record dropped, exactly 1 line in user terms, no `previous-*` copy | M-I3 (`link` removed from `_DOCUMENT_DROP_OUTCOMES`) → RED |
| R-32 (R12 bind spelling) | `test_b100_document.py::test_tc_b100_29_r12_bind_keeps_the_unresolved_spelling` | app rooted under a junction above the work-area anchor; after Save project of a pasted entry the editor's `source_path` equals `app.workarea / P / patches / changes.json` (case-folded text compare); vacuity guard: that spelling differs from its resolved form | M-I2 (bind to `PlacementResult.path`) → RED |
| R-33 (R13 `gathered` not carried on an open-project save) | `test_b100_save_guards.py::test_tc_b100_05_r13_open_project_save_does_not_carry_gathered` | P records `gathered` `patches/boost.json`; Load P, Save P → the written `gathered` lacks the row; `active_document` still carried (vacuity guard) | M-I1 (merge-union for every save) → RED |
| `classify_active_document` direct | `test_b100_document.py::test_tc_b100_29_gather_classifier_names_each_of_its_four_classes`, `..._never_copies_a_linked_source`, `..._home_spelled_in_another_case` | `in_home` / `outside` / `inside_elsewhere` / `missing` each from its own source; wrong home for the kind → `inside_elsewhere`; a symlinked source → `missing`; `P/Patches/boost.json` on a case-folding FS → `inside_elsewhere` (Windows only; skips elsewhere with a named reason) | not mutation-probed at integration (named) |
| R-12 | — | stays a named gap, as ruled | — |

## 5. Runs

- GREEN: `evidence/inc-8a/green-01-new-and-touched.txt` (one complete serial run, 22:35:32Z–23:00:43Z, 25 min 8 s): **643 passed, 1 failed**. The one failure is `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound` (225 scanned vs 224 declared: the tester's new module). Fixed by RP-I2 (test-only bump); `test_id_registry.py` then re-ran inside the guards run: 13 of 13 passed. No timing node failed; no node was re-run alone. tc_29 second-save passed inside the full run.
- Guards: `evidence/inc-8a/guards-01.txt` (23:01:06Z–23:03:14Z): **75 passed, 0 failed**, snapshot report "29 snapshots passed" — 0 snapshot cells changed, nothing regenerated.
- Mutation probes: `evidence/inc-8a/mutants-integration-01.txt` (7 mutants, all RED on their nodes; sources restored byte-identical, hashes in the header).

## 6. Risks / notes for review

- **Ruling 3 on a document text that names a data file.** `active_document: "firmware.s19"` now paints `not readable  firmware.s19  a recorded entry has the wrong shape - replace the file, or Save project to drop it` while the image `firmware.s19` opened fine, and `merge_load_problems` keys by file text, so a real problem on the image (e.g. `changed on disk`, rank 3) would merge with this row (rank 2 wins). Applied as ruled; flagged for `qa-reviewer` / the orchestrator.
- **Reason wording for out-of-form values** ("a recorded entry has the wrong shape") reads oddly under `not readable`; it is the reader's user-term reason, kept per the ruling.
- `proto-8a-app.md`'s example "(HLR-170 invalid arm …) → 1 `manifest damaged` row" is superseded by ruling 3; the graph file was not edited (spec record).
- The `manifest_problems` docstring Summary still says "one `manifest damaged` problem per finding"; its Data Flow names the exception. Cosmetic.
