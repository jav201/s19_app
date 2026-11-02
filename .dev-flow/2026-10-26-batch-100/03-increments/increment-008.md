# Increment 008a — HLR-170 / LLR-170.1–170.3 · `the active change document is recorded and reopened (M-2, D4; LED .61 positive arm; LED .63 plan rows; B-06 / A-15 arms)`

| Field | Value |
|---|---|
| Batch | `2026-10-26-batch-100` |
| Increment | `008a` |
| Lane | `main` · 4 SOURCE files (`app.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py`) — 4/4, at the cap |
| Requirement(s) | `HLR-170` · `LLR-170.1` · `LLR-170.2` · `LLR-170.3` · `LLR-167.8` (positive arm, LED .61) · `LLR-164.2` (merge carry, B-06) · `LLR-167.6` (document row, merge, F4 clause) · `LLR-168.3` (`active_document` carried) · `LLR-169.2` (A-15 arm) · `LLR-169.3` · `LLR-169.4` · `LLR-169.5` · US-160 |
| Acceptance | `AT-B100-08` (`tests/test_b100_document.py::test_at_b100_08_saved_document_reopens_with_the_project`, 118 and 220) and the Inc 8a arm of `AT-B100-20` (`tests/test_b100_active_variant.py::test_at_b100_20_inc8a_every_writer_carries_the_active_document`) · white-box `TC-B100-28 · -29 · -30` (new) · `-70` (positive, failed-write and file-backed arms) · `-05` (merge carry) · `-59` (document row, merge) · `-20` (`active_document` carry) · `-22` · `-23` · `-24` · `-25` |
| Interfaces | consumes B100-I1 / I2 / I3 / I13 / I16 / I21 (Inc 7), the Inc 5 seam, the Inc 6 / Inc 7 helpers; adds the `active_document` key to `KNOWN_MANIFEST_KEYS` (additive) |
| Agent | design-first experiment (`experiment-8a/PLAN.md`): E1 requirements · E2 Code-Wire prototype (graph only) · E3 code-free design review (architect + security, 3 rounds) · E4 parallel build (3 implementers + tester) · E5 change validation. Models: Opus throughout; one Sonnet design pass was redone on Opus (§6) |
| Date | `2026-10-30` (E5 corrective pass and close run into 2026-10-31 UTC) |
| Base | `dc3b314` (Inc 7 final); tree uncommitted at the time of writing |
| Import proof | `<HOME>\Github\s19_app-b100-inc8a\s19_app\__init__.py` — printed in every transcript header (`# s19_app.__file__` / `# s19_app import:`) |

---

## 1 · What changed

**The feature (HLR-170).** Save project records the Patch Editor's change document as `active_document` in `project.json`; Load reopens it into the editor; a bad, missing or unwritable document is listed or named and the load or save continues.

- **LLR-170.1 — the key and its one predicate.** `active_document` is a known top-level key holding one `patches/<name>.json` or `checks/<name>.json` project-relative path (`.json` case-insensitive). One predicate, `is_active_document_form`, is imported by the writer and the reader (S-11). It also refuses C0/C1 control characters (R6), Unicode format characters (SEC8a-4) and any text the manifest-keys mode refuses (device stems, trailing dot or space — F1). The reader parses it first (`_parse_manifest_active_document`) and gives one issue plus `None` for a refused value; the writer refuses a value outside the form and emits it last. The four in-project writers carry it (`_manifest_carry`).
- **LLR-170.2 — Save project writes and records.**
  - A **pasted** document (no `source_path`, at least 1 entry) is written through the one placement (`_write_editor_document` -> `place_into_workarea`, guard on the UNRESOLVED destination) as a NEW file in the home for its kind: `changes.json`, `changes_1.json` on a name clash with different bytes, reused when the bytes are equal (immutable reuse, LLR-155.3 holds with no exception — E3 R1). After the write the editor's document is bound to `project_dir / home / name`, unresolved (R12).
  - A **file-backed** document already in the target's home is recorded as on disk (plan action `keep`) and never rewritten; one outside the project is copied by the gather (`new`). `classify_active_document` (R11) classifies it as `in_home` / `outside` / `inside_elsewhere` / `missing`, deciding "inside" on the unresolved text and `lstat`-ing the source and its parent (R18); `inside_elsewhere` and `missing` give 0 document rows and one status line.
  - The save is never refused because of the document. A failed write, a refused landing or a junctioned home gives one status line in user terms, no `active_document` of its own (a merge or an open-project save carries the target's value — R3), and a rollback that removes only what this save created (`created_home` joins `created_dirs`).
- **LLR-170.3 — Load reopens.** One classifier, `recorded_document_state` (R10): two `lstat` (home and file; a link -> `link`), size cap 1 MiB from `st_size` before any open (`too_large`), one bounded read, guarded parse of THOSE bytes (`ValueError`, `RecursionError`, `TypeError` -> `unreadable`; a 5 000-digit integer included — R19), entry cap 1 000 only when `entries` is a list, `OSError` -> `io_error`; only file-level codes make a document unreadable (R17). The reopen installs the parsed document into the session's `ChangeService` (no second read, no history pushed), after the A2L, with the A2L context. A document that cannot be reopened is exactly one `not readable` problem (reason in user terms, step mark picks the next step — F5); `missing` stays owned by `check_project_files` (LLR-169.5); the project still loads and Load plus panel stay under 1 s at the caps.
- **LLR-167.8 — positive arm.** When Save project completes after the app wrote the editor's document, the panel's dirty flag is cleared (`mark_saved`); a refused, failed-write or file-backed-dirty save keeps it (the file-backed case now holds on the natural path: Load P -> edit -> Save P -> flag True, one status line naming the Patch Editor save). An unparsed paste buffer keeps the flag.
- **LLR-164.2 — merge and open-project carry.** A merge carries `gathered` (target rows plus this save's rows) and `active_document` (carried, or the session's placed document); an open-project save does NOT carry `gathered` (R13). Save project drops a carried `active_document` only on `missing`, `link` or `unreadable` (with one status line, painted at commit and only when the carried record is the one written — R15); it keeps it on `too_large` and `io_error`. A refused target value is a skipped entry: `project.json.previous-<UTC>` is kept and named (R5).
- **LLR-167.6 — the plan.** The plan names the document row (`new` / `keep`; `replace` is not produced through Inc 8a) and, in a merge, the `project.json` row `merge` (only when the target holds a `project.json`); `manifest_keys` holds `active_document` exactly when written. After the commit step decides nothing is recorded, the handler settles its plan (`_plan_without_document_key`) so the plan's key list equals the written keys — the F4 clause now written into the LLR (LED .75).
- **LLR-169.2 / .3 / .4 / .5.** The seam's `files` covers the active document (5 keys with `patches/boost.json`, `patches/other.json` absent; a missing document gives no record, 0 raises); verify's drift domain includes `active_document`; the reader accepts the `files` key equal to the accepted `active_document` and refuses other sub-folder keys; `check_project_files` reports a recorded `active_document` absent from disk as `missing`, with and without a `files` record, and `_missing_recorded` never names the document for a missing variant (R7).
- **R20 (E5 pre-ruling).** A refused or unreadable `active_document` problem is labelled `change document <text>`, so it never merges with a data file of the same name; out-of-form reason `the recorded change document path is not one the app can use`. `document_problem_file` is the one producer of the label for the four problem sources.

**Corrective pass 1 (E5, 11 items; `experiment-8a/E5-cp1-notes.md`).** F1 (device stems: the form refuses them, the gather no longer lists a copied row the key mode refuses), R20 + F5 (label and `step` marks), F2 (same-file lines: `_unrecorded_document_lines`), F3 (wording for copied-but-not-named and in-home-but-out-of-form), F4 (plan settled after the outcome), F6 (test gaps), F7 (one `_plain_entry`, `stat` import removed from the gather), F8 / F9 / SEC8a-5 (docstrings, no exception class in the first containment message, one claim in the double-fault rollback), SEC8a-1 (exact-text project compare), SEC8a-3 (`_document_home_contained` before a pasted or copied row), SEC8a-4 (format characters). SEC8a-2 is recorded only.

**Inc 7 deferred items (LED .70) — discharged in E5.** Round-3 code and security review of Inc 7 corrective pass 2: done, closed (tag `inc7-cp2`; findings F9 and SEC8a-5 fixed in cp1). Inc 7 security probes re-run: done (`evidence/inc-8a/security/inc7-rerun/`). Guards on Inc 7's final bytes: covered by the Inc 8a guards. Inc 7 full reverse census: moved to the batch-end full battery (§7).

**Process decision (operator ruling, 2026-10-30).** Per increment, run only the tests of the new or modified requirements, the modules that exercise the changed functions, and the guards. No reverse census and no full suite per increment; the full battery runs once when all increments are done. This packet applies it: the reverse-census checklist row is marked not run, never met.

## 2 · Files modified

| File | Kind | Traces to | Change |
|---|---|---|---|
| `s19_app/tui/app.py` | source | HLR-170 · LLR-170.2 · LLR-170.3 · LLR-167.8 · LLR-164.2 · LLR-167.6 · LLR-168.3 · LLR-169.2 | `recorded_document_state` (the one classifier, R10), `_reopen_active_document`, `_write_editor_document`, `_handle_save_dialog` (document write, bind, record, commit-step lines, merge carry, drop/keep by outcome, rollback), `_plan_project_save` / `_plan_without_document_key`, `_save_manifest_keys`, `_write_and_verify_manifest`, `_manifest_carry`, `_handle_load_project` reopen after the A2L, `_unrecorded_document_lines`, `_document_home_contained`, `_restore_manifest(already_kept=)`; `_parsed_paste_text` in the session snapshot names. Final sha256[:16] `ebc6dbf4d1b6aa98` |
| `s19_app/tui/services/manifest_writer.py` | source | HLR-170 · LLR-170.1 · LLR-169.2 · LLR-169.3 · LLR-169.5 · LLR-168.3 | `serialize_manifest` (`active_document`, document checked first and emitted last), `write_project_manifest` pass-through, `verify_written_manifest` drift domain, `project_file_records` (document record, two `lstat`), `check_project_files` / `_disk_problem` / `_active_document_missing` (`missing` for the document, R20 label), first containment message without the exception class. Final `254693df5dcdf38a` |
| `s19_app/tui/services/variant_execution_service.py` | source | HLR-170 · LLR-170.1 · LLR-170.3 · LLR-169.4 · LLR-169.5 | `KNOWN_MANIFEST_KEYS` + `active_document`, `ProjectManifest.active_document`, `is_active_document_form` (one predicate), `_parse_manifest_active_document`, the `files` key equal to the accepted document, `document_problem_file`, `DOCUMENT_REASON_*` and next-step marks (`ProjectFileProblem.step`), `manifest_problems` (refused document -> one `not readable` row), `_missing_recorded` suffix restriction, `_plain_entry` (shared), `manifest_keep_reason` text. Final `699c38bd2cce77cd` |
| `s19_app/tui/services/project_gather_service.py` | source | HLR-170 · LLR-170.2 · LLR-167.6 · LLR-164.2 | `classify_active_document` (4 classes), `document_in_home`, `gather_project_artifacts` (names the landed document, unresolved source, no `gathered` row the key mode refuses), `plan_project_save` (document row, merge `project.json` row `merge` only with an existing `project.json`), `PlannedFile.source` / `role` / `home`, `GatherOutcome.active_document`. Final `bd6f926590c17abd` |
| `tests/test_b100_document.py` | test | HLR-170 · LLR-170.1 · LLR-170.2 · LLR-170.3 · LLR-167.8 | NEW. 49 functions / 128 nodes at E4, 161 nodes after cp1 (TC-B100-28 / -29 / -30 / -70 arms, classifier, gather classifier, painted text, R20, F1–F6, SEC8a-1/-3/-4 arms) |
| `tests/test_b100_project_check.py` | test | LLR-169.2 · LLR-169.3 · LLR-169.4 · LLR-169.5 | 9 functions (TC-B100-22 … -25 active-document arms); cp1 re-pins to the `change document <text>` label |
| `tests/test_b100_save_image.py` | test | LLR-167.6 · LLR-167.8 | 9 functions (TC-B100-59 document row and merge, TC-B100-70 positive / failed-write / file-backed arms); re-pins RP-1, RP-3, RP-4, RP-5 |
| `tests/test_b100_save_guards.py` | test | LLR-164.2 · LLR-164.4 | 9 functions (TC-B100-05 merge carry, R5, R8 refined, R13, R15); SEC8a-5 re-pin |
| `tests/test_b100_active_variant.py` | test | LLR-168.3 | TC-B100-20 / AT-B100-20 `active_document` carry across the writers (4 nodes) |
| `tests/test_b100_reuse.py` | test | LLR-170.2 | RP-2: placement calls 7 -> 8, exactly one in `_write_editor_document`, passing `workarea_root` |
| `tests/support/b100_manifests.py` | fixture | LLR-170.1 · LLR-169.4 | active-document manifests (`V1_DOCUMENT` with `"entries": []`, hostile and boundary documents) |
| `tests/support/b100_projects.py` | fixture | HLR-170 · LLR-170.2 | held-file, document-project and Save-project drivers for the 8a arms |
| `tests/test_id_registry.py` | config | HLR-170 | `EXPECTED_SCANNED_TEST_FILES` 224 -> 225 (`tests/test_b100_document.py`), with the history comment |
| `tools/e13/run.py` | test | LLR-167.8 · UX-26 | orchestrator-owned (not the implementer's, not reviewed by the two reviewers): scenario `pe-document` (a project reopened with its active change document) |
| `tools/e13/capture_all.ps1` | test | LLR-167.8 · UX-26 | orchestrator-owned: `pe-document` added to the capture plan (8 plans x 3 sizes) |
| `.dev-flow/2026-10-26-batch-100/01-requirements.md` | doc | HLR-170 | E1 / E3 edits (LED .72, .73, .74) and the LLR-167.6 F4 clause (LED .75) |
| `.dev-flow/2026-10-26-batch-100/01-requirements-ledger.md` | doc | HLR-170 | LED .72 – .75 |
| `.dev-flow/BACKLOG-CODE.md` | doc | HLR-170 | seven items opened at the close (§6) |
| `.dev-flow/2026-10-26-batch-100/experiment-8a/*` | doc | HLR-170 | the experiment records: `PLAN.md`, `steps.log`, `E1-scope.md`, `E3-*.md`, `E4-*-notes.md`, `E4-mutants.md`, `E5-cp1-notes.md`, `codewire/*`, `baseline-inc7-timing.md`, `timing.py` |
| `.dev-flow/2026-10-26-batch-100/03-increments/{review,security}-increment-008.md` | doc | HLR-170 | the reviewers' records |
| `.dev-flow/2026-10-26-batch-100/evidence/inc-8a/*` | generated | HLR-170 | transcripts (evidence table at the end of §4) |

## 3 · How to test

```bash
# from the worktree root; interpreter <HOME>/anaconda3/envs/s19env/python.exe
# new and touched requirements (the module set of green-01 / green-cp1):
env -u NO_COLOR PYTHONUTF8=1 PYTHONDONTWRITEBYTECODE=1 PYTHONIOENCODING=utf-8 PYTHONPATH=<worktree> \
  python -m pytest -q -p no:cacheprovider tests/test_b100_document.py tests/test_b100_project_check.py \
  tests/test_b100_save_image.py tests/test_b100_save_guards.py tests/test_b100_active_variant.py tests/test_b100_announce.py \
  tests/test_variant_execution.py tests/test_manifest_writer.py tests/test_manifest_verify.py tests/test_project_gather.py \
  tests/test_tui_manifest_save.py tests/test_b100_reuse.py tests/test_b99_staging.py tests/test_b100_session_reset.py \
  tests/test_tui_variants.py tests/test_id_registry.py   # the 16 modules of green-01 / green-cp1
# guards:
python -m pytest -q -p no:cacheprovider tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py \
  tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py
# reviewers' probes (unedited): evidence/inc-8a/review/test_r8a_probes.py, test_r8a_round2_probes.py
# security probes: evidence/inc-8a/security/probe_app.py, probe_k_case.py, probe_u_classifier.py, inc7-rerun/run_all.sh
# mutants: experiment-8a/E4-mutants.md (71 rows) + E4-integration-notes.md (M-I1 … M-I7); cp1: evidence/inc-8a/cp1/mut-spec-cp1.py
# NOT run per increment (operator ruling): the reverse census and the full suite -> batch-end battery (§7)
```

## 4 · Test results

Evidence home: `.dev-flow/2026-10-26-batch-100/evidence/inc-8a/`. **Final source hashes** (sha256[:16], printed in the header of every cp1 transcript — `guards-cp1.txt`, `green-cp1.txt`, `green-cp1-rerun.txt`): `app.py` `ebc6dbf4d1b6aa98` · `manifest_writer.py` `254693df5dcdf38a` · `variant_execution_service.py` `699c38bd2cce77cd` · `project_gather_service.py` `bd6f926590c17abd` (pre-cp1 / integration hashes: `8c627b717172ccd8` · `a638b23d2bb861b1` · `5f2ab3268d9cdc4d` · `6f2d419ea0d2ee56`; base `dc3b314`). Import proof in every header: the worktree's `s19_app\__init__.py`; `NO_COLOR` unset.

**Scope (operator ruling, 2026-10-30):** new and modified requirement tests, the modules that exercise the changed functions, and the guards. No reverse census, no full suite. The runs below are exactly that and no more.

| Layer | Owed in | Nodes | Result |
|---|---|---|---|
| **A · white-box** `TC-NNN` <-> LLR | `core` · `full` | TC-B100-28 / -29 / -30 (`test_b100_document.py`, 161 nodes after cp1) · TC-B100-22 … -25 (`test_b100_project_check.py`) · TC-B100-59 / -70 (`test_b100_save_image.py`) · TC-B100-05 / -07 (`test_b100_save_guards.py`) · TC-B100-20 (`test_b100_active_variant.py`) · TC-B100-01 re-pin (`test_b100_reuse.py`) | `executed` — E4 integration: **643 passed, 1 failed** (`green-01-new-and-touched.txt`; the one failure, `test_id_registry.py::test_tc607_scanned_corpus_matches_the_declared_bound`, was the new test module not yet counted: fixed by the 224 -> 225 bump, re-run inside the guards: 13 of 13). After cp1, on the final bytes: **655 passed, 10 failed** (`cp1/green-cp1.txt`, 29:44): 7 stale pins re-pinned (R20 label, `stat`, two claims) and 3 environment failures (a 1.076 s timing node while mutants shared the CPU; two path-depth guards that refused the `--basetemp` I used); the 8 failing ids re-run alone with the default temp dir: **11 passed** (`cp1/green-cp1-rerun.txt`); the 2 R20 check-side arms added after the run started: **2 passed** (`cp1/green-cp1-supplement.txt`) |
| **B · black-box** `AT-NNN` <-> story | `core` · `full` | AT-B100-08 (new), AT-B100-20 Inc 8a arm | `executed`: `green-at-08-20.txt` 19 passed; RED `red-at-08-20-vs-base.txt` 4 failed (behavioural) |

### RED counterfactual — executed, not predicted

| Kind | Transcript | Result |
|---|---|---|
| E4 tester's 164 nodes (and the re-pinned ones) vs base `dc3b314` | `red-01-vs-base.txt` | **160 failed, 4 passed** (3:49). 101 behavioural failures and 59 on the new symbols (`ImportError`: a pure helper that does not exist at base; each has its behavioural RED by a mutant). The 4 passes are boundaries and controls that hold at base |
| cp1 arms on the pre-cp1 snapshot | `cp1/red-cp1-vs-pre.txt`, `cp1/red-cp1-vs-pre-repins.txt`, `cp1/red-cp1-vs-pre-supplement.txt` | **33 failed, 4 passed** of 37 selected; the 7 re-pins fail on `pre`; supplement 2 failed. The 4 passes by design: a fixture fix proven by a mutant (R-19), the M-15 arm proven by a mutant, the held-file classifier arm, the unchanged `[restored]` id |

### Instrument RED-proof

| Oracle | Proof that it can fail |
|---|---|
| the round trip of `active_document` | the manifest is parsed with the stdlib `json` in the test; M-01 / M-02 (skip the reader's prefix rule, drop the writer's check) RED |
| the reopen classifier | the 5 outcomes asserted on real files (links, held file via `CreateFileW` share mode 0, 1 MiB of `[`, a 5 000-digit integer); M-I1 … M-I7 and R-17 / R-19 mutants RED |
| the bound at the caps | `time.perf_counter` around the real handler; M-26 (Save project parses a too-large merge target instead of keeping it unread) RED by timing alone (34.2 s with the mutant, 2.07 s on base under the same load, `mut-M-26-base-rerun.txt`) |
| rollback removes only what the save created | the tree diff of the project before and after, with the user's identical `changes.json` present; the rollback mutants RED |
| painted text | 0 issue codes and 0 class names asserted on the painted status and panel text |

### Mutation verdicts (C-40)

**E5 run on the integration tree** (`mutation-summary.md`; copies of the tree in four lanes, 23:05–23:15 UTC; every transcript `mut-<id>.txt` ends `restored = True`): **78 rows = 71 from `E4-mutants.md` + 7 integration mutants M-I1 … M-I7. 72 KILLED, 5 SURVIVED, 1 not-run.** (R-26b, an extra arm, was also KILLED and is not counted.)

| Verdict | Mutants | Disposition |
|---|---|---|
| KILLED | 72 | each failure line read for a behavioural assertion, not only the return code |
| SURVIVED, equivalent | M-10 (the extra `missing` row from the reopen merges with `check_project_files`' row, so the painted announcement is identical), R-10, R-11 (`UnicodeDecodeError` and `JSONDecodeError` are `ValueError` subclasses) | no test can kill them; R-10 / R-11 vanished with F7 (the two catch-set entries were deleted) |
| SURVIVED, test gap | M-15 (wrong target: the source was deleted, so the digest was never called), R-19 (`V1_DOCUMENT` had no `entries` key, so the R17 step was never reached) | both killed in cp1: `cp1-M-15`, `cp1-R-19` |
| not-run | R-12 (`TypeError` removed from the classifier's catch set) | no input raises `TypeError` in the classifier; named gap, backlog (`mut-R-12.txt`) |

**cp1 run on the final tree** (`cp1/mut-spec-cp1.py`, `cp1/mutants-cp1-run.log`; copy `mutcp1`, never the worktree): **22 runs: 20 KILLED, 2 SURVIVED** (`cp1-R20-check`, `cp1-R20-missing`: wrong target — the truncated document's bytes match its record, and a recorded missing document is `_disk_problem`'s row) -> new arms -> `cp1-R20-check-b` and `cp1-R20-missing-b` KILLED. Mutants covered: F1 (`cp1-F1`, `cp1-gathered`), R20 (`-reopen`, `-reader`, `-reason`), F5 (`cp1-F5`, `-step`), F2, F3 (`-copied`, `-inhome`), F4, R-17, R-19, M-15, SEC8a-1, -3, -4, -5.

**Not claimed:** the 78 mutants ran on the pre-cp1 bytes; the 22 cp1 mutants cover what cp1 changed. The 78 were not re-run on the final tree.

### Emitted-form assertion (C-42)

| Artifact | Assertion on the emitted form |
|---|---|
| `project.json` | parsed with the stdlib `json`; `active_document` and `files` equal to `hashlib` records; the key absent when nothing is recorded (byte-identical to the Inc 7 golden) |
| the written document | `P/<home>/changes.json` re-read with the change-document parser; bytes equal to `serialize_change_document` |
| the status line / panel | painted `#log_line_4`, `#status_text`, `#result_body` renders; 0 codes, 0 class names |

### Guards and snapshot cells

| Run | Transcript | Result |
|---|---|---|
| guards on the integration bytes | `guards-01.txt` | **75 passed, 29 snapshots passed** (2:05); no snapshot cell changed |
| guards on the final bytes | `cp1/guards-cp1.txt` | **75 passed, 29 snapshots passed** (2:49); no snapshot cell changed. The first attempt (`cp1/guards-cp1-run1-basetemp-artefact.txt`) used my own `--basetemp` and `TC-016s` refused that temp path by design: 1 failed, 29 snapshots passed — an artefact, rerun with pytest's default temp dir |
| the census sweep (`-k census`) | — | **not run** (operator ruling; batch-end battery) |

### Reviewers' probes on the cp1 tree

`cp1/review-probes-cp1.txt`: **7 passed, 1 failed (Q4)**. Q4 spies the plan predicted before the write; the pass settles the plan after the outcome (`_plan_without_document_key`). The orchestrator and the code reviewer (round 2) accept this as meeting LLR-167.6; the clause is written into the LLR (LED .75).

### Security probes

`security/out_U.txt` (classifier, 4 466 fuzzed documents, 0 raises outside the catch set), `out_APP_W.txt` (pasted write containment), `out_APP_SGD.txt` (S1–S9 hostile merge targets, G0–G3 gather classifier, D1–D4 timing), `out_K.txt` (case-sensitive `P` / `p`), `out_C2.txt` (both caps through the real Load dialog). Inc 7's six probes re-run verbatim: `security/inc7-rerun/`.

### E13 (C-UX-5) evidence

Orchestrator-owned captures, real Windows Terminal, 8 plans (`pe-clean`, `pe-saveback`, `pe-saveback-closed`, `pe-problems`, `pe-damaged`, `pe-patched`, `pe-unreadable`, and the new `pe-document`) x 3 sizes (118x54, 220x60, 99x54) = **24 PNGs** in `evidence/inc-8a/e13/`, one row each in the evidence table below. Gate passed (2026-10-31T00:40Z).

### Experiment step table (from `experiment-8a/steps.log`; UTC)

| Start | End | Step | Agents | Outcome |
|---|---|---|---|---|
| 2026-10-30 20:12:29 | 20:20:36 | E2-baseline | 1 x Opus | graph 25 nodes, extractor exit 0 (py3.12), 5 candidates C1–C5, 4 requirement-text notes (agent wall 7.3 min) |
| 20:12:29 | 20:24:38 | E1 | 1 x Opus | 1 HLR / 11 LLR / 2 AT / 11 TC in scope, 12 requirements edited (LED .72), slice 22 nodes, 6 open questions (3 decisions) |
| 20:25:36 | — | E2-decisions | orchestrator | 6 E1 questions decided (LED .72 addendum, 4 LLR thresholds), `interfaces-8a.md` fixed |
| 20:25:36 | 20:34:51 | E2 | 3 x Opus parallel | A app 9 nodes / 66 examples, B writer+gather 8 nodes / ~75 examples, C reader 9 nodes; graph only after operator correction (no source change); 3 design defects (B), 1 HIGH seam risk (C R1 = A R-6 = B P-B1), 13 interface proposals |
| 20:35:47 | — | E3-prerulings | orchestrator | 12 rulings on 13 proposals + seam risks |
| 20:35:47 | 20:56:00 | E3-r1 | 2 x Opus parallel | architect FAIL (5 MAJOR / 6 MINOR / 3 LOW, 9.5 min), security FAIL (0 HIGH / 4 MAJOR / 5 MINOR / 3 LOW, 20 min); all on design, no code |
| 20:57:23 | — | E3-rulings | orchestrator | R1–R7 (R1 drops the in-place rewrite: closes 6 findings) |
| 20:58:00 | 21:06:54 | E3-fix | 1 x Sonnet | design pass R1–R7 + 20 prototype edits, 6 LLR amended (LED .73); OBS: Sonnet truncated `proto-8a-writer-gather.md` twice and rebuilt it from its own `cat -n` output |
| 21:07:00 | 21:16:00 | E3-r2 | 2 x Opus parallel | architect FAIL (2 MAJOR / 3 MINOR / 4 LOW, 8 min), security FAIL (2 MAJOR / 2 MINOR / 4 LOW, 9 min); round-1 findings all closed; A3R2-5 = content lost in the Sonnet rebuild |
| 21:16:55 | — | E3-rulings-r2 | orchestrator | R10–R14; design pass 2 on Opus |
| 21:16:59 | 21:29:33 | E3-fix2 | 1 x Opus | design pass R8–R14 + 13 reviewer fixes (LED .74), no line loss |
| 21:30:37 | 21:36:42 | E3-r3 | 2 x Opus verify | architect PASS-WITH-NOTES (3 MINOR / 2 LOW, 5 min), security PASS-WITH-NOTES (1 MINOR / 2 LOW, 6 min) -> PDR approved |
| 21:37:23 | — | E3-close | orchestrator | R15–R19 addenda to E4, token rows amended |
| 21:37:38 | 22:19:20 | E4 | 4 x Opus parallel | C reader 13 min (195 existing pass), A app 26 min, B writer+gather 27 min, tester 41 min (164 nodes; RED 160F / 4P: 101 behavioural + 59 import on new symbols; 71 mutant rows) |
| 22:20:42 | 23:03:33 | E4-integration | 1 x Opus | 6 rulings applied, 6 re-pins, 7 gap tests + 7 mutants; GREEN 643 passed (1 registry count fixed), guards 75 passed, 0 snapshot cells changed |
| 23:05:38 | 23:35:00 | E5 | 3 x Opus parallel | mutants 10 min (78: 72 killed, 5 survived = 3 equivalent + 2 test gaps, 1 not-run); code review 18 min FAIL (1 MAJOR design-gap F1; 4 MINOR, 4 LOW; impl 5 / design-gap 3 / inc7-cp2 1); security 30 min PASS-WITH-NOTES (0 / 0 / 0 / 5 LOW; impl 1 / design-gap 3 / inc7-cp2 1); Inc 7 cp2 round 3 closed |
| 23:36:35 | 2026-10-31 00:30:00 | E5-cp1 | 1 x Opus | 11 items fixed, 22 mutant runs (20 killed + 2 survivors re-killed with new tests), GREEN 655 + reruns, guards 75, probes 7/8 (Q4 accepted by the orchestrator) |
| 00:40:08 | — | E5-r2 | code-reviewer | PASS-WITH-NOTES (F1 closed, 2 LOW) 9 min; E13 24 captures -> gate passed; close records start |

First step start to the last logged step: 20:12:29Z to 00:40:08Z = about 4 h 28 min wall, against Inc 7's 687 min (`experiment-8a/baseline-inc7-timing.md`). Inc 8a is smaller than Inc 7, so wall time alone does not decide (`PLAN.md`); per-LLR time, where each MAJOR/HIGH was caught and the number of corrective passes are the comparison the operator reads. Raw facts for it: **E3 (design, no code) caught 9 MAJOR in round 1 and 4 MAJOR in round 2, 0 in round 3; E5 (code) caught 1 MAJOR (F1, tagged design-gap) and 0 HIGH; 1 corrective pass; 0 full-census launches** (Inc 7: 2 corrective passes, 6 full-census launches, 8 MAJOR/HIGH-class findings, all found on code). The conclusion stays with the operator.

### Evidence files — bytes at a declared home, verbatim, hash-verified (C-59); digests are of the committed blobs (git normalises line endings, so a Windows checkout of a text file may differ by CRLF)

| Evidence artifact | Path — under `.dev-flow/2026-10-26-batch-100/evidence/inc-8a/` | SHA-256 |
|---|---|---|
| green-cp1-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/green-cp1-rerun.txt | e8742c22558f8424e1ee16c1bc36dedbca9a02f0518c88b64a046c1949257233 |
| green-cp1-supplement.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/green-cp1-supplement.txt | 4fc351399a418ae197dbfa6662c176af3d312f93322de2b49edbbbcf99b7a565 |
| green-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/green-cp1.txt | fa36992bb379f130b9bb1dcd92e329839f5df6d84c128c09ed0e9b910e74f920 |
| guards-cp1-run1-basetemp-artefact.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/guards-cp1-run1-basetemp-artefact.txt | cf88900628184fbd19ae0c91fb00a7eefa8dd1c78c5f252f364c5ccf92ead9bd |
| guards-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/guards-cp1.txt | 0371cf2d70a8328827692e65338e44c03bc8926471f9766dfb898b6a8d549205 |
| mut-spec-cp1.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/mut-spec-cp1.py | 12e94b2a47013e676d177660f8337c1da62b029bf32a60c3e111d08e024e4c31 |
| mutants-cp1-run.log | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/mutants-cp1-run.log | 6cb97b35ebf8ef1e569d01286b67a25357d029423d2894f600bd44bf50fefbc5 |
| red-cp1-vs-pre-repins.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/red-cp1-vs-pre-repins.txt | bff1cb0013d9a7e71010163e84d5ae5900ffe8c53a449ab34548ecbb7f4862f6 |
| red-cp1-vs-pre-supplement.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/red-cp1-vs-pre-supplement.txt | c8ef557c2280dd42630612aae2cd44f7bd53c9a7348f68c946a805ea26ad4d2c |
| red-cp1-vs-pre.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/red-cp1-vs-pre.txt | 5dd69ffd325ba10c96f8c1b8a4a5659bbce67b4afdbe59164682407f1a9841bc |
| review-probes-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/cp1/review-probes-cp1.txt | e1bb2bace4eaa5a81e15dde9a38776db689cc64f814620dc3781aebdae6329ca |
| pe-clean.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-clean.118x54.png | c25c82902020184827851ea1ce0c5104ac44a0b6a644da14e032d70489d2df35 |
| pe-clean.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-clean.220x60.png | c8dd9be6c0e8599379664e30344857bd447a0603e21cfbd23b25df25ba8eb878 |
| pe-clean.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-clean.99x54.png | 3a0356dff00014011434b338e06e4db686d50a1675ddc9d5f47dad9057b6f4dc |
| pe-damaged.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-damaged.118x54.png | 1186b99f12b60f50bdf67db920b7d16cd97cbe56a67a1397ddfe66ace7e34298 |
| pe-damaged.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-damaged.220x60.png | 98f08f79e9737de5ad17ce8dc28d9c5f76122db7248ce7441c3da43306ab2f2c |
| pe-damaged.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-damaged.99x54.png | d8e709523945f05417a87b46e12ed7fce167899e94d6fa6091631549545f531f |
| pe-document.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-document.118x54.png | 5f6bd01fe5187b3ddb76a52bde75b42f7e20021fe63f8e990140ed92aededd12 |
| pe-document.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-document.220x60.png | ac8467be62190f6a5e0715664f77ed21df62d62ccd2b7173c10e1b7b918c7ea0 |
| pe-document.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-document.99x54.png | ddec8fe050e5847f5bd23c8fc9647fa0b7195ad715ecd817d1b094be39267e8b |
| pe-patched.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-patched.118x54.png | a4930c12009429e8ac3ea0bbdb47cf4c428eccec45898f55240756bd216b4e32 |
| pe-patched.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-patched.220x60.png | 42b89e8716c768a1d94b63591d0d56e22581cadfa518f83521cdf2c1e518cde2 |
| pe-patched.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-patched.99x54.png | 527bf6c82f1673568a68f65cee271fe35cd7acb1a3228ab78911f1350373c6ca |
| pe-problems.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-problems.118x54.png | 7f832497d21d0a635802852cb86b9829167ec075d5b0211666f73386b6c6574e |
| pe-problems.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-problems.220x60.png | 25353e3b3decaadde1fdde2d30024c4be7927ef1633eb3ed952fa2a2bd71a80f |
| pe-problems.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-problems.99x54.png | 233f7fcdb4f193616df612ca64180f6666b9475dee53d86e437437cac4137aa7 |
| pe-saveback-closed.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-saveback-closed.118x54.png | 50f67149755e8e626f25a9dc74e9f9d20c5c1c41f71ec515d6e51dae0b9adb06 |
| pe-saveback-closed.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-saveback-closed.220x60.png | 19168db47f0d45dd401854fd6a03fc97cbb01c2571dcf65f8744df4d90adf886 |
| pe-saveback-closed.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-saveback-closed.99x54.png | a1e8a887913ddae48778666a96f5677fe867ea9479894d170139b7753e54e206 |
| pe-saveback.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-saveback.118x54.png | 72da9f765a5731cb50f07ca523d8deac498420f7cff5214bd7ee30c17cba76a3 |
| pe-saveback.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-saveback.220x60.png | b29f3be04c86f09f6ce516b2e1a9b895aa264a14eb3c58ab12dfef769774a36a |
| pe-saveback.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-saveback.99x54.png | 63f3e5cccce8e7685db7da06771bb23c306f8bae0a816e98ceedd259aee4cbb0 |
| pe-unreadable.118x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-unreadable.118x54.png | 0d76a0e6ea53a170ab6009252814ea223d154635bf7d0869ec899219d953e572 |
| pe-unreadable.220x60.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-unreadable.220x60.png | 9c476caf42f16489f2b067991d4c18a8657b5f2cfc6472510b8119aad4474cf5 |
| pe-unreadable.99x54.png | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/e13/pe-unreadable.99x54.png | b771181d49de9e982e67850d7674c9dd8edabf6564bf161354f1c87c30a4df92 |
| green-01-new-and-touched.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/green-01-new-and-touched.txt | 0272c284560a5482feee2a93058538e1797a779dd8535bda5607135cc5545144 |
| guards-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/guards-01.txt | 44776e7e6e6439c248f85e3eab395e8ece5db6dfd782456df093d24538517332 |
| mut-M-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-01.txt | 164f7ebfd4e9d7c8fe7e7ae4f3868c70fd68372ed7cb6ca9c362fb917cc5a2cc |
| mut-M-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-02.txt | 90d15848a173e35c44f01d4cf218a6573abc991b0f3b9415fae2a58eaaac6403 |
| mut-M-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-03.txt | 881d9192c34a2e3b6134f488725c7123de90eb414d22e4a6a3b0a412575b64c5 |
| mut-M-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-04.txt | 29043c6e3205e614072081408e4fce6d3a44788903957119bb12f2639f715e31 |
| mut-M-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-05.txt | 0a8e073099aa43dfb799dbeee183d7691e61ad9f3438d3b798f3c1b129a9ee3a |
| mut-M-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-06.txt | 3aa5c3e3fc598172da77ed2c16236475bde15cb64857bceff37a5d0a167d9274 |
| mut-M-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-07.txt | 8bf549cf310acbdbd9d8d242ccb4bce440f2465ad18f49f424fd6914f7ce82f8 |
| mut-M-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-08.txt | 1417ca02fad9057dee7906f40c2c92fd788462db15a354443a254debe5747cdb |
| mut-M-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-09.txt | 8500979e2373531c1f9141a131d0dc388dfcb7c8aebb162c3b9809e9c3c02f0e |
| mut-M-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-10.txt | e1cc6bf7a6d467aca654ff61e86df0fcbba59215c2f8ddfd71ddbf797617f042 |
| mut-M-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-11.txt | b92168336d5ce846019ed8ec35182c82d7ea4d75dcec35571cc245f02efd55a7 |
| mut-M-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-12.txt | c31d4ed10ea614a4d2cc688d79281b17ef649ff9aa75351f2f77997f8f0c3b9b |
| mut-M-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-13.txt | 2687857b8c430e55a3dc4bfe44ab1a92066870fb575f540e56bc2f891b747c1a |
| mut-M-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-14.txt | 105da6477164a5f94defe19a4fc7c5c33cdff734f2d36205fbce7e2bd0b2a150 |
| mut-M-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-15.txt | f9bf2756497ead7663edd734db2a3c1a25ae2644ba209d881425cfb8f343f581 |
| mut-M-16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-16.txt | 8c5f6b9bbb0c7baedfae517d0748f764113cc546d90703610bfad6953ca2c4d9 |
| mut-M-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-17.txt | 9d2fd8b6a135be386d9061a55fbbb9eadf187f46ef8d2da2fd66f4b3afd04f74 |
| mut-M-18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-18.txt | d6e8352ade1b2938ab3fba2acd65809b404a7d141d581902637744968b314ee4 |
| mut-M-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-19.txt | 393ccc3897adb43d700aeb9f0ff2da27e151662ebeb1f32ea9e5fa2d57ed54f9 |
| mut-M-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-20.txt | 6eae0c851b067663fb8400552072f1addaa7615be4b21cb05f10fa08201663e7 |
| mut-M-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-21.txt | 552e609421d3ea35397c3f0f9670a6c6b400992ebb212716f666f80f089283bd |
| mut-M-22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-22.txt | a3b783dc8548dcfcb38b6dfccb748a4759a3713b84eedc27ca960f85a15f8c4a |
| mut-M-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-23.txt | d9862ccd785b996336dba620447523bc49cdbb09480ccd99f4f1ee69bb60f4dc |
| mut-M-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-24.txt | 15287edf40aabd925070ddc94999e96c317f37c555d43afd2555c46b46ee0b56 |
| mut-M-25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-25.txt | 6e9380e3eb25e6c60f7b5750270ab8e7fe0ba9a75ab5ec910198ac99035bc17c |
| mut-M-26-base-rerun.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-26-base-rerun.txt | b21090d0f67104a8a2b8ead7c2cd151059828d60b7f243116ae8b3171abc1458 |
| mut-M-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-26.txt | dbc407b814984c9e6897c2a058f9e07fc1c2c9580a424f58b51cc1f5330c782c |
| mut-M-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-27.txt | 1af1ee527b58c0be1e4b48720932d5414e219afb918c62319cf2179f43144148 |
| mut-M-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-28.txt | 413bd0e436eefe52fd2d8680b0befd1fa9d877c38b30f11b8d0f14c1f25b9f99 |
| mut-M-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-29.txt | 973114dcb47eea42715e814aed9bf019903e3ffdb630db66e69ef786821e92da |
| mut-M-30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-30.txt | 10b03c274ce4b3591f8ef54d397e71ca902c49cabb25321c15a0ad4db654fabb |
| mut-M-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-31.txt | c90beb679980d7edfca9db2c544e849c32f02afba7a5d2728c19e86cc389207b |
| mut-M-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-32.txt | 2f9162c1966ed92e86f2b205ad15f80169df4bb556afec84cbd9bab2b5859ad4 |
| mut-M-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-33.txt | c8aeb75c38d35cfcb556f6a00d2d67aefff652d1fd3743213ad7af8c1bf5e9f5 |
| mut-M-34.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-34.txt | e40ec6094e5750266a1193b09d1ef0d6aee217a1f9bf0f383158b8661f75dae5 |
| mut-M-35.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-35.txt | 94213a77db5ddb36179ab1e2aabc1dbdc41f7db914af025a28ffe0eab715c6d5 |
| mut-M-36.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-36.txt | 6a7c537f2b3d9eaac5f3f52ec327eeea840ac19ace9b72951cbc6a5619bc1275 |
| mut-M-37.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-37.txt | 37266dfa9d531ef52e5a426286b49a66dd5d35fa4ba94fba9aaf573333baaa09 |
| mut-M-38.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-38.txt | 7010d486703c173a1092270bdb5e7b934d4261780c7ace15cce83848366f0b63 |
| mut-M-I1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I1.txt | 515bd1a96f2a49c4454cd6223d42e2ab213bb62f88bec10a57589d79dd03b30f |
| mut-M-I2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I2.txt | 8b44a6be1880e482b8c539220ccb882d76944173b0bdd0997db67cfc4678fa31 |
| mut-M-I3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I3.txt | 1d47fe0902fdce6b5eb81574da526619cbe438e2be036c612df82f3f2d3625ce |
| mut-M-I4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I4.txt | 2cddbb37dad94dfcdaa94ac7a900ed5b33e21d0cb96c395a6a50ec1da7af9422 |
| mut-M-I5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I5.txt | a5b2e69fe7d1b2f9044460f557455f094d7835e76674e5cf84addcd40e3840a2 |
| mut-M-I6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I6.txt | 58f8cbea6babcca8ce28e89273a7a815d755ce19b2d77b982b48fe4bb6c099ad |
| mut-M-I7.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-M-I7.txt | ac698f6b30e371deb12c2785fe08dbba052b23f43fb99e2b849a723676599b60 |
| mut-R-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-01.txt | 873e3f0c759c86daa1d0737abb1882e9434936b9ced9d9c02dfc6c153786e4e4 |
| mut-R-02.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-02.txt | 089c09296237aaf05399467b7421002642f227e27facbb922a5129f4c52adbc7 |
| mut-R-03.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-03.txt | 024f933d1cd72a658adaca6431cd5f279046c6240d335be553022cf26194574d |
| mut-R-04.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-04.txt | 7841de9f697179284c110df6ad7cb6e6fa40e10c925c9c2c065235bbe7953598 |
| mut-R-05.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-05.txt | 51646d8976ce1160b1d9b1f56bb40196011bc600701152d1a79a501917f75e23 |
| mut-R-06.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-06.txt | 84f0579b6e54e2318068ed136562d73abc91fc5c96111c7ea280217add78d70e |
| mut-R-07.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-07.txt | cb455f06b1b04d108500f2d7e30208fe96147b1d8e91d2e680ead1eed74cbb14 |
| mut-R-08.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-08.txt | 79e20a0fad74cdddcdc25c8646034cb3e2be4af0fb5541be412c797b1d46172b |
| mut-R-09.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-09.txt | b5ac94b2411cb38fbf4898dd51f165adf903f5ac3349a09025f94d757655d595 |
| mut-R-10.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-10.txt | 0f0e23fa9eb9f55899bdc516c3bac81a2d84a495b50271040469de71c84d979f |
| mut-R-11.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-11.txt | 5df7c58d9ace0d8325171d18654cd8a7560f2a44c3e8a857298a6d7408ed2240 |
| mut-R-12.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-12.txt | d1d42fe3f1c79fa3c32079e52e36156cc0cdbaf1b543d9cbaf77f48ff2f70f29 |
| mut-R-13.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-13.txt | 5e9dcea714b7cb41c45bbd3accdc25d04bd0e02c0b550df3f12c3376f42bd6d2 |
| mut-R-14.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-14.txt | 8807c9450776b0150f9e87a8adee89d084ad6442982218fbbed3362bf530e265 |
| mut-R-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-15.txt | 68df382923f49678179a7ad2f8b7bb9dc538e22abe550887210a559dd3ca83fe |
| mut-R-16.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-16.txt | ee71750a55efd2a531d44a2b5f523d27a508a01943f545681566df7b0966601d |
| mut-R-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-17.txt | 56612037e7cbd46d3e03d0a11cf21739b8e8dc859d05608785a70b0c57c8e012 |
| mut-R-18.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-18.txt | 4f4d4cc42c45a2c5ad5dd7a70ea2993b772307ae650213dd170d8eaa5e9c3fd3 |
| mut-R-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-19.txt | 0c62ac2b9d0dafcc7f0a8ca00c4a49b5f317bbb8c746bfc6ab9aaa0f36a69965 |
| mut-R-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-20.txt | e91536d4b18cba775c329750ec9987049879e0ad5a1d34231cdbb41869225084 |
| mut-R-21.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-21.txt | 541abfadc22ccf21bee7513a8af2e5ea1e7d8c7607b542b2d73f8d6bebf1555e |
| mut-R-22.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-22.txt | 6e7d8457d1463493490457d20742f87a916b79476bc2449f2216769d0319f509 |
| mut-R-23.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-23.txt | 2fa00cffeb5b927a564c63e6701687cedd8da56c5b563928d5041dc65427fec5 |
| mut-R-24.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-24.txt | 35acfbd06f7bbbf1413ec9532560d85a80bd588128da6a89934694e665744d8b |
| mut-R-25.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-25.txt | 74aa9f040147b4f828729cd06959f37c2e0ab1c87fa2f6867a7cb639e30f9c2c |
| mut-R-26.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-26.txt | 602337d9e99282a99275cf8f87df02e1611a8cc89c8ee2ed5bc89ef703992384 |
| mut-R-26b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-26b.txt | b2066e62db433d15b4f3ce5a15e8d9c4366ad059560f070ea500aa6e9f7f1fba |
| mut-R-27.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-27.txt | 7bd514e2e9ee77e03dd16d401fc9391281f6f21c1333ad583d93bcc7bd869132 |
| mut-R-28.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-28.txt | 0b5c0d660a2bf53c2788f75a057f22db9aa2a58d197e7c62869f9aaec1a24c17 |
| mut-R-29.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-29.txt | e5bf5116c09d9396a48ed04d5abe85f8baf1a2b4923a9b31e440ce899670799a |
| mut-R-30.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-30.txt | 98b1a8a7bd16aa6bb9b2a0da78a1858e804458432c39fa7ad6590d253f036d04 |
| mut-R-31.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-31.txt | 39668eb3b293b78fc420c2a8936f69089a7ccf160e31525a9fa13b4d92fd473e |
| mut-R-32.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-32.txt | 442655c4bba84c24491d8ae0d1d7e9cfd1eb78fa421c461a46ce5f5f91a9d431 |
| mut-R-33.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-R-33.txt | d7cc1bf70862c9fec8e757691c4e070a06d2a55aee04bb78ef64218854f18dcd |
| mut-baseline-laneA.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-baseline-laneA.txt | 335e093475b17e2045126214eb2d6a1634cac9a43476037c33a86c2f2544bbfa |
| mut-baseline-laneB1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-baseline-laneB1.txt | ba768d2acb3f8ed118cc73cee9782a3e30c47caac1d9e51378bffddc8e1a43f2 |
| mut-baseline-laneB2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-baseline-laneB2.txt | b6a876880d3fa9fe07150ced04813d09f65bb3322aa7895ebf8340bf228e3771 |
| mut-baseline-laneC.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-baseline-laneC.txt | 867bd8c561a49a8587ae9dc59c7430c0366343930f70fdd0d7afb1ccc78674cd |
| mut-cp1-F1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F1.txt | 92918ecf32110f6383344ab977350233252bd2fb41da16fbcfcd7c775d6fae2d |
| mut-cp1-F2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F2.txt | 4e3e49fadec43c370e886ab583ed2121bb896adc2aaec1b989b7966368a86359 |
| mut-cp1-F3-copied.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F3-copied.txt | 61ab5d0be0169b62c2a05daa9296e04e1de245a7c6a8e25a3ac1477aba6df25c |
| mut-cp1-F3-inhome.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F3-inhome.txt | 5e306b42e9b216f307ed296bbd842bc7757689922008d1b9f2c1173a4d8e1788 |
| mut-cp1-F4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F4.txt | 9ef425a160dcf3f1218e16395a5a8bdbdaf0ac790ca95783122bc3c01610d034 |
| mut-cp1-F5-step.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F5-step.txt | 842e35fcf32e10017cab445d5796609fa90be9718070b359d70b908d77ffd3d3 |
| mut-cp1-F5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-F5.txt | 0fd97f429a02e0634b91be3fe286f6fe3d65c81ebb85b2eefd99ca34b3b18388 |
| mut-cp1-M-15.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-M-15.txt | 2b87421e19a54d653c7d75e576e3d6535163f352908bada529f33df6d699c9e3 |
| mut-cp1-R-17.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R-17.txt | 22f67bc89dbc3e8510f82a4dfd3fe10f61c4c9c2665cb669191f0646e9f7fa77 |
| mut-cp1-R-19.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R-19.txt | c79bf587d281e0ea04356413bb27807b6b9593a09140808e661a0b98e7bfc932 |
| mut-cp1-R20-check-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-check-b.txt | ece1cc630e71de387de34deb7469560998e8bfa0c5b4587685e0002db1f54d71 |
| mut-cp1-R20-check.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-check.txt | 154d1b13726b94c29c10918ab43df131c6f00a9e0db5380922fc5ccd64731b02 |
| mut-cp1-R20-missing-b.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-missing-b.txt | 15e7c36d47e3af82659910005f3ed8de7c027348a7063a55b4ea434a1dcbb89c |
| mut-cp1-R20-missing.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-missing.txt | 9f1ef39d17070ab024cc3998df9967d124abc58db3083b464f1d094a1a1f7982 |
| mut-cp1-R20-reader.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-reader.txt | dd2e3f9a5bb2e89e35dd89c43497b1db7b6a98809d27fa45c7422ee2a68e00d0 |
| mut-cp1-R20-reason.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-reason.txt | fd05e65c27e924b719b3cbd034520ca23fce70f4b4f41590a91ce9d29cc51e9d |
| mut-cp1-R20-reopen.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-R20-reopen.txt | 0a3934eb98afae47ddbc06b5cb72832df07c440049189350b0fe1be25d1c4833 |
| mut-cp1-SEC8a1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-SEC8a1.txt | 7384d46e2ddff35962fc08139c1b10705c5fa48d1ec1d8f1bb49beaf88d98bb7 |
| mut-cp1-SEC8a3.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-SEC8a3.txt | 7a9bdfa2dd6261ab5bb11f44b79b53cafe36b6fe091a3aee3ba13e14208c9b2d |
| mut-cp1-SEC8a4.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-SEC8a4.txt | 8ae8f2ba0b057bda04a9fe6c038605cc27b8ce0810d22df3a7e3ecd478060d41 |
| mut-cp1-SEC8a5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-SEC8a5.txt | 5b1efa871951726b7bbb8af839652bb0003b69bfc74c4018a774cff262a7e62e |
| mut-cp1-gathered.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mut-cp1-gathered.txt | 17785845fe82f99ac6e91e5dc0c833d7e6476fb2798590cccaddb0d4a18bce66 |
| mutants-integration-01.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mutants-integration-01.txt | e2f9ab9040a7b70df97296ab39f409252ebdf2c0f7af026cb75998aed4a7406f |
| mutation-summary.md | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/mutation-summary.md | 7868a1c8229ecb6f6600e625f08853d3d246ef4136babdf0dfa5c6afa5f46ba2 |
| red-01-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/red-01-vs-base.txt | 56b443deef8811487ee52ade2b47c675d84d06857439b1087a445946dc422e7a |
| probes-r8a-q5.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/probes-r8a-q5.txt | f5b2e9c854dc2a45c98d5a4a6dc816541437772c744ace4767509fac4259b180 |
| probes-r8a-q6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/probes-r8a-q6.txt | 527c56372be2c48b42ea484960356a23456703cb755dac50c68b7ee569a5cc21 |
| probes-r8a-round2-cp1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/probes-r8a-round2-cp1.txt | 5a4d63812875cba826dae826f66e82b92b04357ed7ff3c3417cbe91ec946aba0 |
| probes-r8a-round2-q1-q6.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/probes-r8a-round2-q1-q6.txt | db598ae6a7fb159e377efa0b54e5dbdea3be75b4a6edd93276957f32e8ae9536 |
| probes-r8a-run1.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/probes-r8a-run1.txt | 7e8567eeb530f381d73bdc2027159d5013b74e8272b4c92e5c184f0daaaf69a0 |
| test_r8a_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/test_r8a_probes.py | 551090cff45c2d3c77be2f452555d6c05ae292f8c70a97492264ed7035d011ca |
| test_r8a_round2_probes.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/test_r8a_round2_probes.py | 1e9b016ae696acea974b42fe2ec73f85290d127e418c0ff3b581a9b29a1b156a |
| common.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/common.py | aed0018f7ecd3c5f41afa1b51e39ee8c872380238b72f31a810225fb83640b73 |
| probe_c2.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/probe_c2.py | ab9ed1e196f8fcfcdd5179dcb6eb194b3c28dd1c77dbc57d54378c705582306f |
| probe_c_composite.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/probe_c_composite.py | d9537309926bed169c48195a9211e1792e27c0c7ad42ab5981c1792bf9085231 |
| r3_out_probe_a_dos.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/r3_out_probe_a_dos.txt | 0987cb41bb27a91149b28c544056e04e6a61a01587e29964c14046557b3c6d1a |
| r3_out_probe_e_load.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/r3_out_probe_e_load.txt | 2a9ddb5d2e6a34d7fa818685c41394bf506653dd2e3e9b14af33d606a5835c4d |
| r3_out_r2_probe_s.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/r3_out_r2_probe_s.txt | 7a829dcd529130f5fb8e5f0b7137dca50bba789b3c0981ab59b8cdeb401904a3 |
| r3_out_r2_probe_t.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/r3_out_r2_probe_t.txt | 65cef34bb729d272ae7f405d5e29eabc7dc492d97fdd8b419f599508e381b01a |
| r3_out_r2_probe_w.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/r3_out_r2_probe_w.txt | fa73548f711672576857006e329b3a70f3067e06a3c1e433bef1e80659051dc9 |
| r3_out_r2_probe_w2x.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/r3_out_r2_probe_w2x.txt | 1de69eff7758394fbfd7ec014696c549227fc020c035554a37fd35327cd3eb21 |
| run_all.sh | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/inc7-rerun/run_all.sh | 729dfe4842b75040d8bdd53e04564e87cf12f16e9cb4971bfdadd18f89e76408 |
| out_APP_SGD.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/out_APP_SGD.txt | 1221036250a109f85d23b570cc2939491162c3f17491ef75b38558d969694a9b |
| out_APP_W.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/out_APP_W.txt | f7dc9fc7b61e3f95018967cb8b600eef14a5ccb7b5989a4e2277221ef85a0393 |
| out_C2.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/out_C2.txt | 235c58913d5845627d27c4ddc7b466e0a727422bb9355b9a8b2f088e6a8540c0 |
| out_C2_doc_saveback.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/out_C2_doc_saveback.txt | 2bc5cd0b53598d7d81bfa739dda96d3830c8dd6e62760bf587ad4c9d61639c8f |
| out_K.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/out_K.txt | a122a5db30d11e4d96e2be33ccad723582fc4e9cdcd800e00ae4cf21b1615fd1 |
| out_U.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/out_U.txt | 7cb5b64383b6cc9d1c45d08d88d417b58f267bf50c3fac8c5fcbd69266d112b4 |
| probe_app.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/probe_app.py | d73f33af156cae67380d3b06380cafc5a4f1444b880d5a0c753f85a8be27fce0 |
| probe_k_case.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/probe_k_case.py | e70834ca3efff3a447ccb622532699592e92113b717471c89de32bc3a497fb8d |
| probe_u_classifier.py | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/security/probe_u_classifier.py | a42beb1b65ef064779eeaf0097c05f8175f4a608c3422fa2749b4d41e8a93b94 |
| E1-scope.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E1-scope.md | 7d100c390e63bd3b39990dcee699af22dd4e0285bb309f0789b3515a5439744d |
| E3-architect.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E3-architect.md | 2cf22ea3bd191b5c691b508d120f0a63f040be811dd60b36880ab7abd6ba81b1 |
| E3-rulings.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E3-rulings.md | 77688e47f4ec3aa933ee2ad4c971632a6e300d7a2e5a61a1cbdfab551013689c |
| E3-security.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E3-security.md | b6dc7948cc7b6d32672b8f7968aea7444ddadab2167463b89256e5790844132f |
| E4-app-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E4-app-notes.md | a2633ff5daeb88ee20c28870abdf48060dbf7398230d81968299e26dc074fb52 |
| E4-integration-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E4-integration-notes.md | 676c039fabd6f3d6a83ef5a5928e032048103d1a01dc5d01b67c0de589c46676 |
| E4-mutants.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E4-mutants.md | fb3c83bc1ab40e049bbdd454dc87c4f0b9ee5d11bb03f7426b4b16851754f8a9 |
| E4-reader-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E4-reader-notes.md | d3903ef9b45a680f08b46c417b0f932873e73223357f6df211bc37e5419748c0 |
| E4-tester-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E4-tester-notes.md | 1e023270ab8a8ebe44650ea32b85d632519c951b0a999595c854b4f81b24f220 |
| E4-writer-gather-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E4-writer-gather-notes.md | 44ff30b3553f98520efadb69dabb7ca8c1cd10428466061aa6b22b28cf1b3e66 |
| E5-cp1-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/E5-cp1-notes.md | 282860a9838e533ae076bfffff1dd8d0f0d7fe2c8935a735fe035f9b7e4bd809 |
| PLAN.md | .dev-flow/2026-10-26-batch-100/experiment-8a/PLAN.md | 67928afaa5854136cd8796e56a4b01c01ac3b2544b6a5db47be16a5c7f3ca96b |
| baseline-inc7-timing.md | .dev-flow/2026-10-26-batch-100/experiment-8a/baseline-inc7-timing.md | f568c5d8d6734fbd7b20f6685ba9e3b9dcfc59926b1373a745819661d32c7928 |
| baseline-8a.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/baseline-8a.md | e800f11b8763db8bf6b8245790adf32e60402e495799f9fa12374aaa439f2127 |
| baseline-notes.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/baseline-notes.md | 81e79b651ad3f86d1c448494b537cadd8bbc08a1ef10a78f80d0acd5ef9e28ec |
| diff-report-py311.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/extract-baseline/diff-report-py311.md | bf32609998023b816a19e986525eee3b2300a1cbb49257e1fd61c038fb0c10d1 |
| diff-report.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/extract-baseline/diff-report.md | 3948db0ff2648bba7c8e32b124c25f08e76d9e2e7cc8d149604ea9f64fdd6517 |
| extract-py311.json | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/extract-baseline/extract-py311.json | 37bbca6cc4be9d59b43ac83118c82ac384026d57baedf3740a105e3fafe379cf |
| extract.json | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/extract-baseline/extract.json | 8448512d0886b58c585104165440152bbc010b1f4d8d50802802cb96525f9b95 |
| interfaces-8a.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/interfaces-8a.md | e79be24d8d894c76bc4504be306c50ef0262696ab249ae9bf808bfcbe9d386d2 |
| proto-8a-app.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/proto-8a-app.md | 610fbd292f75dd060f5b1cbc3cb07e937f5e4e09cba20fef67dc593779efd1fe |
| proto-8a-reader.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/proto-8a-reader.md | 9c70504c4f07df4a247ee137c76d28b7c85e3452643b1cdedf53df3f5b221637 |
| proto-8a-writer-gather.md | .dev-flow/2026-10-26-batch-100/experiment-8a/codewire/proto-8a-writer-gather.md | 07a3268fa4575c559d7f61a1cae5df6c266a5c795168e9333be798bedd2bb476 |
| report8a.py | .dev-flow/2026-10-26-batch-100/experiment-8a/report8a.py | ed2f858205a595d7a4284729a4fc55eb6cc094046f0577e0f3ae9e0949aaf549 |
| steps.log | .dev-flow/2026-10-26-batch-100/experiment-8a/steps.log | bb639ff6a6460c93d46abcfe9219e34496e60b2ed16bdf69115285ef6b7949d1 |
| timing-8a.md | .dev-flow/2026-10-26-batch-100/experiment-8a/timing-8a.md | 9ebc8ed3a51ce561203e71dc8947228d835991b24d02a27835240c35c967ba7b |
| timing.py | .dev-flow/2026-10-26-batch-100/experiment-8a/timing.py | cb045179ee8cbc1b5ee3acecde8abb26cbd656a2e47ef9186c41201d6ce58a05 |
| timing8a.py | .dev-flow/2026-10-26-batch-100/experiment-8a/timing8a.py | e46e3433783019646495c29d3673e833186478e5857593d26d7a520e3f88e330 |
| green-at-08-20.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/green-at-08-20.txt | 3c48f9a314656d263b85e733a4fa166e1a7a3b04f8e5bed5ceb2fcdc0eb50d87 |
| red-at-08-20-vs-base.txt | .dev-flow/2026-10-26-batch-100/evidence/inc-8a/red-at-08-20-vs-base.txt | cae867f062e7d153bec44cb89fff0edded010daef3e9e09aee7a120dbc6f505c |

The 29 rows for `experiment-8a/*` are computed with the same SHA-256 over the file bytes; `devflow-evidence.py` accepts only paths under `evidence/` (and only a packet named `increment-NNN.md`), so those rows and the 172 rows above were assembled from its output and a direct `hashlib` digest, not written by `--write`.

## 4b · Independent review

| Field | Value |
|---|---|
| **Independent review** | `code-reviewer` — spawned as a generic agent with agents/code-reviewer.md · PASS-WITH-NOTES r2 (r1 FAIL `BLOCK — BLOCK-UNTIL: F1`) — r1: F1 MAJOR (design-gap) a change document whose stem is a Windows device name (`aux.json`, `con.json`) made every Save project fail; F2, F3, F5, F6 MINOR; F4, F7, F8, F9 LOW. r2: F1 closed on the diff and by the Q6 re-run, F2–F9 closed (F4 closed by the settle step, accepted), 0 HIGH, 0 MAJOR open; new R2-1 LOW (the gather guard leaves a device-stem flow row out of `gathered` with no status line), R2-2 LOW (a file-backed document with a junctioned home gets the generic reason) — both to the backlog — `review-increment-008.md`, transcripts under `evidence/inc-8a/review/`. Round 3 of Inc 7 corrective pass 2 (tag `inc7-cp2`): SEC7-R2-1 … SEC7-R2-4 and R2-1 … R2-4 sound; F9 found and fixed. `security-reviewer` — spawned as a generic agent with agents/security-reviewer.md · PASS-WITH-NOTES r1 — 0 HIGH, 0 MAJOR, 0 MINOR, 5 LOW (impl 1: SEC8a-2; design-gap 3: SEC8a-1, -3, -4; inc7-cp2 1: SEC8a-5); the code implements the approved design in every executed arm (pasted write contained, rollback removes only what the save created, classifier never raised on 4 466 fuzzed documents, hostile merge targets wrote, copied or deleted nothing in 9 of 9 cases, writer and reader agree on 30 of 30 values); Inc 7 cp2 SEC7-R2-1 … SEC7-R2-4 closed by executed probes — `security-increment-008.md`, transcripts under `evidence/inc-8a/security/`. The security review ran on the pre-cp1 bytes; SEC8a-1, -3, -4, -5 were fixed in cp1 and are verified by their arms, mutants and the inc7-rerun probe, **not re-reviewed**. **Design reviews (E3, code-free):** `architect` and `security-reviewer`, three rounds each — r1 FAIL / FAIL, r2 FAIL / FAIL, r3 PASS-WITH-NOTES / PASS-WITH-NOTES (0 HIGH, 0 MAJOR) -> PDR approved (`experiment-8a/E3-architect.md`, `E3-security.md`). **Orchestrator (2026-10-30/31).** Final source hashes `app.py` `ebc6dbf4d1b6aa98`, `manifest_writer.py` `254693df5dcdf38a`, `variant_execution_service.py` `699c38bd2cce77cd`, `project_gather_service.py` `bd6f926590c17abd`; 4 of 4 sources. Scope ruling in force (operator, 2026-10-30): per increment, the new and modified requirement tests, the modules that exercise the changed functions and the guards only; the reverse census and the full suite run once at the batch end. Rulings applied: R1 – R20 (`experiment-8a/E3-rulings.md`), the 6 integration rulings, F4 accepted (LED .75). |

---

## 5 · Risks

- **No reverse census or full suite was run for Inc 8a, or for Inc 7's cp2 tree** (operator ruling): a test outside the 16 modules that lists a project folder after a Save project with a pasted entry now sees `patches/changes.json`; the tester flagged it and did not search for it. The batch-end full battery is the check (§7).
- **The security review ran on the pre-cp1 bytes.** cp1 changed `app.py`, the reader, the writer and the gather after it (SEC8a-1, -3, -4, -5 and the F1 / F2 / F3 / F5 / F7 fixes). Their arms and mutants ran on the final bytes; no reviewer re-read them. The code reviewer's round 2 did read the cp1 diff.
- **Load at the reopen caps has about 0.2 s of margin** under the 1 s bound (SEC8a-2, backlog); the panel render, not the parse, is two thirds of the cost. Measured on one machine.
- **A pasted document that is saved twice** writes `changes.json` once and `keep`s it afterwards; edits to a bound document are not written by Save project (E3 R1: no in-place rewrite). The flag stays True and one status line names the Patch Editor save. Intentional; it is the immutability rule (LLR-155.3).
- **A file-backed document is recorded as on disk.** Unsaved edits in the panel are not part of what Save project records.
- **AT-B100-08 and the Inc 8a arm of AT-B100-20** are black-box nodes through keys and dialogs at 118 and 220 (`green-at-08-20.txt` 19 passed; `red-at-08-20-vs-base.txt` 4 failed, behavioural). Limits: AT-08's image-byte check cannot fail on its own (the save applies the entry; the no-apply status check and `test_tc_b100_30_reopen_never_applies_the_entries` carry it); AT-20's Execute-scope arm stays with Inc 9b.
- **R2-1 / R2-2 / SEC8a-2 / R19 / A-R14 / R-12 are open LOW items in the backlog**, none blocking.
- **`replace` is not produced** by any plan row through Inc 8a (HLR-175 still names it; outside 8a).
- **POSIX and Python 3.12 were not run** for the 8a arms; Windows junctions, symlinks and held files ran on Windows 11 / Python 3.11.15. The case-sensitive-folder arm skips with a named reason when `fsutil` cannot set the flag (it ran here).

## 6 · Pending items / spec deviations

**Backlog added at the close** (`.dev-flow/BACKLOG-CODE.md`, each with its evidence path): R2-1 (device-stem flow row left out of `gathered`, no status line — tie to Inc 8b), R2-2 (junctioned home gets the generic line for a file-backed document), SEC8a-2 (Load 0.6–0.8 s at the reopen caps), `parse_change_document` "never raises" contract bug (R19, 5 000-digit integer raises `ValueError`), undo depth after the reopen (A-R14), R-12 not-run mutant, and the known CI flake below.

**Known CI flake.** `tests/test_b97_flow_execution.py::test_tc_b97_64_a_new_set_run_restarts_the_dwell` failed once in CI (Inc 7 run 41121137306) and passed 3 of 3 locally on `dc3b314`. Compare the FAILED set against it before reading a red CI run as a regression.

**Named gaps.** AT-B100-08 / AT-B100-20: written after E5 (see above); AT-20's Execute-scope arm → Inc 9b. E3 R13 had no node at E4 and got one in the integration pass (`test_tc_b100_05_r13_open_project_save_does_not_carry_gathered`, M-I1). R-12 (above). OBS-7-1 stays an observation (no code change; LLR-178.1's wording says the match is against a `files` record).

**Model observation (E3-fix).** A Sonnet design pass truncated `proto-8a-writer-gather.md` twice and rebuilt it from its own `cat -n` output; round 2 found the content that was lost (A3R2-5). The pass was redone on Opus with no line loss. Design work moved to Opus; Sonnet is limited to mechanical work.

**Finding -> disposition (E3, code-free design review).**

| Finding | Severity | Disposition |
|---|---|---|
| A3-1 (one problem text `patches/boost.json` everywhere), A3-5 (`created_dirs` for the document write), A3-6 … A3-9, A3-10 (`_parsed_paste_text` in the snapshot names), A3-11 (`_missing_recorded`), A3-12, A3-14 (a–g) | A3-1 … A3-5 MAJOR, rest MINOR / LOW | closed in round 2 by the prototype edits and R1 – R7 (LED .73); A3-13 record-only |
| A3-2 (a carried document whose file is absent), A3-3 (a session document that was not placed), A3-4 (a file-backed document in the target's home) | MAJOR | R2, R3, R1 (LED .73) |
| S3-1 (the reopen unbounded: 33 s at 20 000 entries) | MAJOR | R4: 1 MiB / 1 000 caps before the parse -> R10 classifier |
| S3-2, S3-3, S3-4 (in-place rewrite: LLR-155.3, rollback deleting a user file, a write through a junction), S3-10 | MAJOR / LOW | withdrawn by R1: no in-place rewrite, no restore list |
| S3-5 … S3-9, S3-11, S3-12 | MINOR / LOW | R5 (refused target value kept as `.previous-<UTC>`), R6 (painted text in user terms, control characters refused), S3-8 (records walk the document's components), S3-9 (two `lstat`, absolute path), S3-11 (document checked first, emitted last), S3-12 (examples aligned) |
| A3R2-1 (planner and gather disagreed on a document; its digest could refuse the save), A3R2-2 (two document classifiers), A3R2-3 … A3R2-9 | A3R2-1, -2 MAJOR | R11 (one gather classifier), R10 (one document classifier), R8 refined, R9, R12, R13, R14 (LED .74); A3R2-5 = content restored after the Sonnet rebuild |
| S3R2-1, S3R2-3 (classifier catch set; a hostile merge target), S3R2-2, S3R2-4 … S3R2-8 | S3R2-1, -3 MAJOR | R10, R8 refined (drop on `missing` / `link` / `unreadable`, keep on `too_large` / `io_error`), R12 (bind spelling), R5 clipping |
| A3R3-1 … A3R3-5, S3R3-1 … S3R3-3 | MINOR / LOW | R15 (carried-record line at commit), R16 (one `io_error` reason and next steps), R17 (file-level codes only), R18 (unresolved source, parent `lstat`), R19 (`ValueError` in the catch set); A3R3-4, A3R3-5 record only |

**Finding -> disposition (E5, code).**

| Finding | Severity / tag | Disposition |
|---|---|---|
| F1 device-name document breaks every save | MAJOR / design-gap | fixed in cp1: the form refuses device stems, the gather lists no row the key mode refuses; arms Q6 as a node, form / writer / reader arms; mutants `cp1-F1`, `cp1-gathered` KILLED; closed in r2 |
| F2 same file painted as both "not recorded" and "stays recorded" | MINOR | fixed (`_unrecorded_document_lines`); Q1, Q3; `cp1-F2` KILLED |
| F3 wrong reason for a copied or in-home document | MINOR / impl | fixed (wording keyed on plan row + `GATHER-DOCUMENT-NOT-RECORDED`); Q2; `cp1-F3-copied`, `-inhome` KILLED |
| F4 plan keys list `active_document` after a failed write | LOW / design-gap | fixed with a declared limit (plan settled after the outcome, `_plan_without_document_key`); probe Q4 fails as written by construction; accepted by the orchestrator and by code-reviewer r2 as meeting LLR-167.6; clause added to the LLR (LED .75); `cp1-F4` KILLED |
| F5 next step looked up by reason text across three modules | MINOR | fixed (`ProjectFileProblem.step` marks; reasons defined once); `cp1-F5`, `cp1-F5-step` KILLED |
| F6 R-19, R-17, M-15 arms did not reach their rulings | MINOR | fixed (`V1_DOCUMENT` with `entries`; held-document Load arm; deleted-source arm); `cp1-R-19`, `cp1-R-17`, `cp1-M-15` KILLED |
| F7 five copies of the regular-file `lstat` test | LOW | fixed (one `_plain_entry` in the reader module; `_DOCUMENT_PARSE_ERRORS = (ValueError, RecursionError, TypeError)`); R-10 / R-11 vanished |
| F8 stale docstrings | LOW | fixed |
| F9 exception class painted in the first containment message (Inc 7 cp2 rule) | LOW / inc7-cp2 | fixed (class in `details["exception"]`, logged by the app) |
| R2-1, R2-2 (round 2) | LOW | backlog |
| R20 label of a refused or unreadable document problem | pre-ruling | applied in cp1 (`document_problem_file`) |
| SEC8a-1 case-sensitive work area, `P` vs `p` | LOW / design-gap | fixed (exact-text compare); arm skips with a named reason when `fsutil` is unavailable (ran here); `cp1-SEC8a1` KILLED |
| SEC8a-2 Load at the caps 0.6–0.8 s | LOW / impl | recorded only; backlog |
| SEC8a-3 planner predicts a landing through a junctioned home | LOW / design-gap | fixed (`_document_home_contained` before the row); `cp1-SEC8a3` KILLED |
| SEC8a-4 Unicode format characters pass the form | LOW / design-gap | fixed (category `Cf` refused at both ends); arms on `U+202E`, `U+200B`, `U+2066`, `U+FEFF`; `cp1-SEC8a4` KILLED |
| SEC8a-5 double-fault rollback paints two contradicting lines | LOW / inc7-cp2 | fixed (`already_kept`); re-pin of `test_tc_b100_07_rollback_keeps_the_previous_copy_unless_restored`; `cp1-SEC8a5` KILLED |

**Orchestrator rulings R1 – R20** are in `experiment-8a/E3-rulings.md`: R1 no in-place rewrite · R2 carried document absent -> dropped by Save project · R3 an unplaced session document counts as none · R4 reopen bounds · R5 refused target value kept as `.previous-<UTC>` · R6 painted text · R7 `_missing_recorded` · R8 / R8 refined drop and keep by outcome · R9 "at least 1 entry" for pasted only · R10 one document classifier · R11 one gather classifier · R12 bind spelling · R13 `gathered` for a merge only · R14 requirement text (LED .74) · R15 carried-record line at commit · R16 one `io_error` reason · R17 file-level codes · R18 unresolved source and parent · R19 `ValueError` · R20 label `change document <text>`.

**Re-pins (test::node — old -> new — requirement).** RP-1 `test_tc_b100_70_unwritten_document_keeps_the_flag` -> `…_written_document_clears_the_flag` (LLR-167.8) · RP-2 `test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root` 7 -> 8 placement calls (LLR-170.2) · RP-3 `test_tc_b100_15_patched_s19_is_emitted` project tree gains `patches/changes.json` (LLR-170.2) · RP-4 `test_tc_b100_59_gather_service_imports_no_change_module` (the `stat` import added, then removed in cp1 with F7; the intent assertion unchanged) · RP-5 `test_tc_b100_59_pending_patch_in_the_open_project` rows gain the document row (LLR-167.6) · RP-I1 `test_tc_b100_30_refused_record_is_one_manifest_damaged_row_and_no_reopen` -> `…_one_not_readable_row_and_no_reopen` (ruling 3, later the R20 label) · RP-I2 `EXPECTED_SCANNED_TEST_FILES` 224 -> 225 · cp1: the bare-label nodes of TC-25 / TC-30 -> `change document <text>` (R20), `test_tc_b100_07_rollback_keeps_the_previous_copy_unless_restored` 2 claims -> 1 (SEC8a-5). Removed: 0.

## 7 · Suggested next task

**Inc 8b** (sub-folders and save-as; the flow rows of the save). Carry into it: R2-1 (a device-stem flow row left out of `gathered` with no status line — the gather guard now applies to every row) and the Inc 8b sub-folder rows of the plan (LLR-167.6, "extended at Inc 8b"). Backlog items opened here are listed in §6.

**Batch-end full battery (owed once, when all increments are done — operator ruling 2026-10-30).**
1. the full reverse census / full suite on the final tree, split as `PLAN.md` E6 says, every failure dispositioned against base (including Inc 7's deferred census, `census-tree-cp2.txt`, and any node that lists a project folder after a Save project with a pasted entry);
2. the guards (`tests/test_import_census.py tests/test_tui_snapshot.py tests/test_id_registry.py tests/test_batch91_registry_hygiene.py tests/test_address_census.py tests/test_engine_unchanged.py`) and the census sweep (`-k census`) on the final bytes;
3. the mutants of every increment re-run on the final tree where a later increment touched the same function (the 78 of Inc 8a ran on the pre-cp1 bytes);
4. the CI run: compare the FAILED set with the previous run and with the known flake `test_tc_b97_64_a_new_set_run_restarts_the_dwell`; the Linux confirmation of CI-6-1 (LED .71) still owed;
5. a security re-read of the cp1 changes if the orchestrator wants SEC8a-1, -3, -4, -5 re-reviewed rather than probe-verified.

---

## Increment gate checklist

| # | Item | Owed in | ✓/⚠/✗ | Evidence |
|---|---|---|---|---|
| 1 | ≤4 source files, or reason declared | all | ✓ | 4/4: `app.py`, `manifest_writer.py`, `variant_execution_service.py`, `project_gather_service.py` — §2; `workspace.py` and `screens.py` untouched |
| 2 | Tests written in this same increment | all | ✓ | `test_b100_document.py` (49 functions at E4, 161 nodes after cp1) + 28 functions in 4 modules + fixtures — §2, §4 |
| 3 | Layer 0 written where the criterion applies | `core` · `full` | ✓ | pure units: `is_active_document_form`, `recorded_document_state`, `classify_active_document`, `document_in_home`, `serialize_manifest`'s document arm, the reader's `_parse_manifest_active_document` |
| 4 | RED counterfactual declared | `core` · `full` | ✓ | `red-01-vs-base.txt` (160 failed, 4 passed vs `dc3b314`); `cp1/red-cp1-vs-pre.txt` (33 failed, 4 passed) |
| 5 | Reverse census declared | `core` · `full` | ⚠ | **not run per increment — operator ruling 2026-10-30, batch-end full battery** (§7). The 16 modules of `green-01` / `green-cp1` and the guards ran; Inc 7's deferred census moves to the same battery |
| 6 | `code-reviewer` passed | `core` · `full` | ✓ | §4b — PASS-WITH-NOTES r2 (r1 FAIL `BLOCK — BLOCK-UNTIL: F1`); the cp1 diff was read in round 2 |
| 7 | No file from another lane touched | all | ✓ | the 4 named sources + tests / fixtures / config / records; `tools/e13/` is the orchestrator's; `prototypes/` untouched |
| 8 | Frozen interfaces untouched (or returned to the trunk) | all | ✓ | `active_document` joins `KNOWN_MANIFEST_KEYS` additively; B100-I1 / I2 / I3 / I13 / I16 / I21 consumed unchanged |
| 9 | Coverage claims verified on disk | all | ✓ | every count cites its transcript; the 78 mutants are stated as run on the pre-cp1 bytes, not the final ones |
| 10 | Load-bearing emptiness declared | all | ✓ | the cp1 R-19 arm uses `"entries": []` so the R17 step is reached; the R20 arms assert 0 rows on the data file as well as 1 on the document; vacuity guards in the Q4 spy (the predicted plan lists the key) and the R12 bind (the unresolved spelling differs from the resolved one) |
| 11 | Mutation verdicts declared — per arm | all | ✓ | 78: 72 KILLED, 5 SURVIVED (3 equivalent, 2 gaps killed in cp1), 1 not-run (R-12); cp1: 22 runs, 20 KILLED + 2 re-killed — §4 |
| 12 | Instrument RED-proof declared | all | ✓ | §4 Instrument RED-proof |
| 13 | Correction population declared | all | ✓ | writers of `project.json`: Save project, save-back, variant append, MAC / A2L sync (all carry `active_document` through `_manifest_carry`); readers: `read_project_manifest` (first key parsed), the Load reopen, Save project's classification of the carried record |
| 14 | Emitted-form assertion declared | all | ✓ | §4 |
| 15 | Independent review names somebody | all | ✓ | §4b — `code-reviewer`, `security-reviewer`, E3 `architect` and `security-reviewer` |
| 16 | Evidence files declared | all | ✓ | §4 evidence table (written by `devflow-evidence.py`) covers `evidence/inc-8a/` and `experiment-8a/`, including the 24 E13 PNG rows |
