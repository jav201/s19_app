# Code Review — Increment 008a (batch-100, "the change document travels with the project", HLR-170 / LLR-170.1–170.3, 167.6, 167.8, 164.2, 168.3, 169.2–169.5) + round 3 of Inc 7 corrective pass 2

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`. I am independent of this code: the E4 implementers (groups A, B, C), the tester and the integration agent wrote it, not me. |
| Tree reviewed | Worktree `C:\Users\jjgh8\Github\s19_app-b100-inc8a`, branch `b100-inc8a`, base `dc3b314`, uncommitted (`git diff dc3b314` + untracked). Source sha256 (16): `app.py` `8c627b717172ccd8`, `manifest_writer.py` `a638b23d2bb861b1`, `variant_execution_service.py` `5f2ab3268d9cdc4d`, `project_gather_service.py` `6f2d419ea0d2ee56`. These equal the hashes in `evidence/inc-8a/green-01-new-and-touched.txt` and in `mutation-summary.md`. I did not edit source or tests. The files I created are this report and `evidence/inc-8a/review/` (probe file and transcripts). |
| Contract (the approved design is the spec) | `experiment-8a/codewire/proto-8a-app.md`, `proto-8a-writer-gather.md`, `proto-8a-reader.md`, `interfaces-8a.md` (pre-rulings 1–12), `experiment-8a/E3-rulings.md` R1–R19 (R20 known-pending: not reported, its dependencies are listed in §R20), `01-requirements.md` HLR-170, LLR-170.1–170.3, 167.6, 167.8, 164.2, 168.3, 169.2–169.5, ledger LED .72–.74. Build notes `E4-app-notes.md` (D-1…D-3, G-1), `E4-writer-gather-notes.md` (D-B1…D-B5), `E4-reader-notes.md` (C-E4-*, D-E4-*), `E4-integration-notes.md` (rulings 1–3, RP-*). Precedent and shape: `review-increment-007.md`. |
| Also in scope | Round 3 of Inc 7 corrective pass 2 (LED .70): the cp2 code in `052dc3a` (unchanged in `dc3b314` and carried under this diff) against `increment-007.md` §1 "Corrective pass 2" (R2-1…R2-4, SEC7-R2-1…R2-4). Findings tagged `inc7-cp2`. |
| Interpreter proof | s19env Python 3.11.15. Probes ran with cwd = worktree, `PYTHONPATH` = worktree, `-c pyproject.toml`, `--basetemp` in the session scratchpad; each transcript prints `s19_app.__file__` = `C:\Users\jjgh8\Github\s19_app-b100-inc8a\s19_app\__init__.py` and the 4 source hashes. `NO_COLOR` unset (`env -u`), `PYTHONUTF8=1`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONIOENCODING=utf-8`, `-p no:cacheprovider`. Per the operator ruling I ran no full suite, no census and no mutants; I relied on `green-01` (643 passed + the RP-I2 bump), `guards-01` (75 passed, 29 snapshots) and the mutation run (`mutation-summary.md`, 72 KILLED / 5 SURVIVED / 1 not-run), and sampled `mut-M-07.txt`, `mut-R-16.txt`, `mutants-integration-01.txt` (behavioural kills, `restored = True`). |
| **Verdict** | **FAIL (reject until fixed).** Recorded token: **`BLOCK — BLOCK-UNTIL: F1`** (0 HIGH, 1 MAJOR that blocks on correctness, 4 MINOR, 4 LOW). This verdict authorises nothing. The increment advances only after I re-read the F1 fix on the diff and re-run probe Q6. F2, F3 and F6 should land in the same corrective pass. |

`…\scratchpad` = `C:\Users\jjgh8\AppData\Local\Temp\claude\C--Users-jjgh8-clde\a8feab43-c248-4ccb-86cf-122b894659b2\scratchpad`. The probe source and every transcript are copied to `.dev-flow/2026-10-26-batch-100/evidence/inc-8a/review/`.

## BLUF

The code matches the approved design. I traced every ruling R1–R19 and every pre-ruling still in force to code, and the build-note deviations (D-1…D-3, D-B1…D-B5, D-E4-1/-2, integration rulings 1–3) are real and justified. One reachable path breaks the design's central promise, and the design review could not have caught it from the prototypes because the gap sits between two predicates the design treated as one:

- **F1 (MAJOR, design-gap):** a change document whose stem is a Windows device name (`aux.json`, `con.json`, `nul.json`, `com1.json`: real, listable files on this Windows 11 host and ordinary names on POSIX) makes **every** Save project fail with "project.json was not written. check the folder.", while that document is open. The app pre-checks the landing with `is_active_document_form` only; the writer also runs the manifest-keys refusal, which refuses device names. Pre-ruling 2 and R11 say the save is never refused because of the document.

The other findings are wrong status text on reachable paths (F2, F3), a plan/written key mismatch on failure paths (F4), fragile text coupling (F5), test gaps the mutation run already exposed (F6), and housekeeping (F7, F8). Inc 7 cp2 is sound; one LOW consistency note (F9).

**Experiment answer (E5 key question).**
- **Does the code match the approved design?** Yes, node for node, with the recorded deviations. No behaviour was invented outside the design.
- **Defects the design review could not see (implementation detail):** F3, F5, F6, F7, F8. These are wording branches, string coupling, fixtures and duplication: none is visible in a prototype graph.
- **Design gaps the review missed:** F1 (the "one form predicate" of pre-ruling 1 is narrower than what the reader and the writer accept, so pre-ruling 2's pre-check is incomplete), F2 (R3 composes "session document not placed" with "carried record kept" without asking whether they are the same file), F4 (LLR-167.6's "plan lists the keys the save writes" was not carried to the document's failure paths).

## Scope reviewed

- `git diff dc3b314` for the 4 sources: `app.py` (+760), `manifest_writer.py` (+210), `project_gather_service.py` (+350), `variant_execution_service.py` (+268). Read in full, plus the context they call: `_EntryWalk` / `_entry_text` / `_walk_manifest_entry` / `_manifest_key_refusal` / `_component_refusal`, `changes.io.write_change_document` / `parse_change_document` / `ChangeService.load`, `_handle_load_project` (reset → manifest → check → A2L → install set → reopen → install), `_handle_save_dialog` from the carry to the commit block, `_abort_save`, `_plan_row_mismatch`, `_gather_copy`.
- Tests: `tests/test_b100_document.py` (new, 55 functions) read for intent where they pin a ruling (TC-28, TC-29, TC-30 reopen/held/refused/linked, R12 bind); re-pins in `test_b100_reuse.py` (RP-2), `test_id_registry.py` (RP-I2) checked against their requirement. Other touched arms read through the mutation table's node list.
- Inc 7 cp2: `_EntryWalk` (exact-text keys, per-node child dicts, folder ceiling), `serialize_manifest`'s one walk, `_resolve_intended_entries`, the SEC7-2 message and its `details["exception"]` → app log, `kept_copies` in the five post-keep rollbacks and `_abort_save`'s confirm-then-remove.

## What I executed (evidence state: `executed`)

| Probe | Transcript | Result |
|---|---|---|
| Q1 — Load P (reopens `patches/boost.json`), the file held by another program, Save project P | `probes-r8a-run1.txt` | **Defect (F2).** Painted: "Change document boost.json was not recorded in the project — it could not be placed in the project's patches folder" **and** "Change document patches/boost.json could not be read — it stays recorded…". `project.json` records `active_document: patches/boost.json`. This also executes the plan's digest-`OSError` arm that mutant M-15 could not reach. |
| Q2 — file-backed `boost.txt` from the common patches folder, Save project P | `probes-r8a-run1.txt` | **Defect (F3).** `P/patches/boost.txt` is copied; the line says "it could not be placed in the project's patches folder". |
| Q3 — P records `checks/boost.json` holding a change-kind document; Load P, Save P | `probes-r8a-run1.txt` | **Defect (F2).** Painted "was not recorded in the project — it is in the project but not in its patches folder"; `project.json` still records `checks/boost.json` (carried). |
| Q4 — forced pasted-document write failure, plan keys vs written keys | `probes-r8a-run1.txt` | **Defect (F4).** Plan `(…, 'derived_from', 'active_document')`; written `(…, 'derived_from')`. |
| Q5 — natural path: paste 1 entry, Save P, Load P, Save P (no edit) | `probes-r8a-q5.txt` | **Holds.** Tree and `derived_from` unchanged by the second save; no entry re-applied (Q6 of LED .72 holds end to end). |
| Q6 — file-backed `aux.json` / `con.json` from the common patches folder, Save project P | `probes-r8a-q6.txt` | **Defect (F1).** Both: "Manifest write failed" + "Project NOT saved: could not save — project.json was not written. check the folder."; P rolled back. The files are real on this host (`os.listdir` lists them; host check in the same session). |

## Findings

| id | Severity | Tag | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|---|
| **F1** | **MAJOR** (blocks: a reachable input makes every Save project fail while the document is open; contradicts pre-ruling 2 and R11; wrong advice "check the folder") | design-gap | `variant_execution_service.py:244-289` `is_active_document_form` (no device-name / key-mode rule); `app.py:9929` (the app records the landing when the form passes); `manifest_writer.py:373-390` (the writer runs `_reject_unsafe_entry` → `_manifest_key_refusal` → `_component_refusal` → `is_windows_device_name`) | **A change document named `aux.json`, `con.json`, `nul.json`, `prn.json`, `com1.json`, `lpt1.json` (any device stem) refuses the whole save.**<br>• The gather copies it to `P/patches/aux.json` and names it; `"patches/aux.json"` passes `is_active_document_form`, so the app passes it to `_write_and_verify_manifest`.<br>• `serialize_manifest` refuses it through the key-mode rule, so `write_project_manifest` returns `None` and the save aborts and rolls back. The toast shows the writer's log text ("…entry that is absolute or escapes the project directory: 'patches/aux.json'"), which is also wrong.<br>• Every later Save project with that document open fails the same way. The reader refuses the same key too (`_entry_text` key mode), so the record could never be read back.<br>• **Why the design review missed it:** pre-ruling 1 calls `is_active_document_form` "the one form predicate" used by the reader and the writer, and pre-ruling 2 has the app check a landing with it. But the reader and the writer both add the key-mode refusal on top (interfaces-8a: "refuses … when `is_active_document_form` is False **or** `_reject_unsafe_entry` refuses it"). The predicate the app pre-checks with is narrower than what the writer accepts. Device names are the only text rule in that difference: `:`, drive/root, NUL, length, parts and a trailing dot/space are already excluded by the form or by the `.json` suffix. | Q6 (2 cases, both "Project NOT saved"). Host check: `aux.json`, `con.json`, `nul.json`, `com1.json` created and listed in a normal folder; `is_windows_device_name` True for each; `is_active_document_form("patches/<name>")` True for each. | Make the one predicate equal the text part of both acceptances: in `is_active_document_form`, also return `False` when `_manifest_key_refusal(text) is not None` (text only, no filesystem call, still total). Then the gather emits `GATHER-DOCUMENT-NOT-RECORDED`, the app records nothing and paints its one line (see F3 for the wording), and the save completes. Arms: (a) TC-28 form predicate refuses `patches/aux.json`, `checks/CON.json`; (b) Q6 as a TC-B100-29 node asserting "Saved project to", no `active_document`, one user-term line, 0 internal codes painted. Mutant: drop the new clause → (b) RED. **Discharge:** I re-read the fix and re-run Q6. |
| F2 | MINOR (false or contradictory status about the document; no data loss) | design-gap (wording: impl) | `app.py:9929-9950` (the R3 branch paints "was not recorded" and then falls back to the carried record); `app.py:10453-10460` (the plan's digest `OSError` → no row) | **When the session document and the carried record are the same file, the save paints "was not recorded" although `project.json` records it.**<br>• Held file (Q1): in the plan, `classify_active_document` says `in_home` but `_file_digest` raises, so no row. At commit the default reason "it could not be placed" is painted, then the carried value (same file, `io_error` → kept by R8 refined) is written with "it stays recorded". Two lines contradict each other.<br>• Kind/home mismatch (Q3): a change document reopened from `checks/` is `inside_elsewhere` for the `patches` home; the line says "not recorded" and the carried `checks/boost.json` is written.<br>• R3 tells the app to carry the target's value "plus the one status line about the document", without asking whether that value is the session document itself.<br>• The same arm is the M-15 survivor: no test reaches the digest-`OSError` branch. Q1 does. | Q1, Q3. | After the R3 fallback, if the session document lies in the project and its project-relative text equals `recorded_document`, do not paint the "not recorded" line. Paint at most the carried line (Q1), or one line that says the record is kept as it was (Q3). Arms: Q1 (Windows-only, share-mode hold) and Q3 as TC-B100-29 nodes: exactly one line naming the document, none containing "not recorded", record present. Q1 also kills M-15 (with M-15 the `OSError` escapes and the save fails). |
| F3 | MINOR (wrong reason painted on a reachable path) | impl | `app.py:9936-9946` (the reason map has `inside_elsewhere` and `missing`; every other case falls back to "it could not be placed in the project's patches folder") | **A document that was copied, or that sits in its home, is told it "could not be placed" / "is not in its patches folder".**<br>• `outside` with a landing outside the form (Q2: `boost.txt` → `P/patches/boost.txt` copied): the gather copies the file and records nothing (D-B3, `GATHER-DOCUMENT-NOT-RECORDED`), but the app paints "could not be placed".<br>• `P/patches/boost.txt` (already in the home, the name fails the form) gives `inside_elsewhere`, so the line says "not in its patches folder" although it is in it.<br>• After F1's fix, a device-stem document takes the first path. | Q2. | Word the case from what happened: when the gather wrote or reused a landing but did not name it (the outcome holds a `GATHER-DOCUMENT-NOT-RECORDED` finding, or `gathered` holds the row), say "was copied into the project's patches folder but is not recorded: its name is not one project.json records". For the in-home non-form case, say the name is the reason, not the folder. Arm: Q2 asserting the copy exists and no line says "could not be placed". |
| F4 | LOW (LLR-167.6 contract on failure paths only; a status line names the document) | design-gap | `app.py:10478-10484` (`_save_manifest_keys(…, active_document=records_document or carried…)`) vs `:9929-9950` (the written value) | **The plan's `project.json` keys list `active_document` when the document write (or the gather copy) then fails and nothing is carried.** LLR-167.6 says the plan lists the keys the save writes; Inc 7 F3 enforced that on the normal path. The plan is decided before the write, so a write failure makes the key list one too long. | Q4: plan `…, 'active_document'`, written without it. | Either state the exception in LLR-167.6 ("predicted keys; a document that is not placed is reported by its own line and drops the key") with a TC-59 arm pinning it, or accept it as a recorded deviation in the packet. No code change needed if ruled. |
| F5 | MINOR (fragile coupling; contradicts the module's own "a mark, never message text" rule) | impl | `variant_execution_service.py:1712-1715` `_NOT_READABLE_NEXT_STEP_BY_REASON` and `:2137-2145` `_next_step` (looked up by reason text); the same strings in `app.py:1770-1775` `_DOCUMENT_REASON` and `manifest_writer.py:1144` (`"could not be read"`); `variant_execution_service.py:203` `_REASON_DOCUMENT_LINK` duplicates `app.py:1771` | **The painted next step depends on three modules spelling one reason identically.** Integration ruling 1 (G-1) was implemented as a lookup by the reason's text. If any of the three spellings changes (R20 is about to change document wording), the lookup silently falls back to "replace the file, or Save project to drop it". That is the next step R8 refined says Save project does not perform for `too_large` / `io_error`. M-I4 kills only a "by kind" mutant, not a spelling drift between modules. | code read; `E4-integration-notes.md` ruling 1 | Carry the next step as data: an optional `next_step` field on `ProjectFileProblem`, set by the two producers, and used by the composer when present. Or one set of reason constants imported by `app.py` and `manifest_writer.py` from the reader module. Add one test pinning `_REASON_DOCUMENT_LINK == app._DOCUMENT_REASON["link"]` if the strings stay duplicated. |
| F6 | MINOR (tests that claim a ruling they do not exercise) | impl | `tests/support/b100_manifests.py` `V1_DOCUMENT` (no `entries` key → refused at "no entries list" before the R17 code step); `tests/test_b100_document.py:1199-1214` (held document at Load: the check's row wins the merge, so the app's `_DOCUMENT_REASON[io_error]` is not guarded at Load); the plan's digest `OSError` arm (`app.py:10455`) | **Three named arms do not reach the code they name.** These are the mutation run's own diagnoses: R-19 SURVIVED (vacuous fixture), R-17 note 7 (killed only by the SG05 node), M-15 SURVIVED (wrong target). Each is a test that looks like coverage of an R17 / R16 / A3R2-1 arm. | `mutation-summary.md` §Survivors and notes 7; Q1 reaches M-15's arm. | `V1_DOCUMENT` with `"entries": []` (the summary's probe shows `CHG-V1-FORMAT` is then reported); for R16 at Load, assert the reopen's outcome directly (`recorded_document_state` + `_reopen_active_document` on a held file, no `files` record so the check emits no row); for M-15, F2's Q1 node. |
| F7 | LOW (duplication; equivalent mutants) | impl | `manifest_writer.py:980` and `project_gather_service.py:229` (`_plain_entry`, identical); `app.py:1806` `_is_link_stat`; existing `variant_execution_service._lstat_state` and `manifest_writer._is_reparse_point`; `app.py:1760-1766` `_DOCUMENT_PARSE_ERRORS` | **Five copies of the "regular, not a link or reparse point" `lstat` test**, two of them byte-identical and added in this increment. `_DOCUMENT_PARSE_ERRORS` lists `json.JSONDecodeError` and `UnicodeDecodeError`, which are subclasses of `ValueError` (already listed). That is why R-10 and R-11 are equivalent mutants. | code read; R-10/R-11 | One helper in `workspace.py` (it already owns `_path_traverses_reparse_point`) when that file is next in budget; the tuple becomes `(ValueError, RecursionError, TypeError)`. Backlog is enough. |
| F8 | LOW (stale docstrings) | impl | `variant_execution_service.py:2008-2012` (`manifest_keep_reason` Returns: "holds an active_document this version refused"; the code returns "holds a change document path this version cannot use"); `manifest_problems` Summary ("one `manifest damaged` problem per finding", noted in the integration notes) | The docstrings describe the pre-R6 phrase and the pre-ruling-3 behaviour. | code read | Update both docstrings. |
| F9 | LOW (consistency with the cp2 rule) | inc7-cp2 | `manifest_writer.py:646-652` (the first containment message of `write_project_manifest`), painted by `app.py:10708-10715` (`notify(detail, …)`) | **SEC7-R2-3 moved the exception class out of the painted SEC7-2 message only.** The first containment message in the same function still paints `{type(exc).__name__}: {exc}` in the same toast. The 8a writer refusals reach that toast with log wording as well (F1's toast). Round 2's R2-4 named this line; cp2 changed only the new message. | code read | Give the first message the same treatment (class to `details["exception"]`, which the app already logs at `:10716-10723`), or record that this toast is out of SEC7-R2-3's scope. |

## Ruling-by-ruling trace (approved design → code)

| Ruling | Where | State |
|---|---|---|
| Pre-ruling 1 (homes in the reader, total predicate, C0/C1 per R6) | `variant_execution_service.py:154`, `:238-289`; TC-28 homes test | holds; **narrower than the writer — F1** |
| Pre-ruling 2 (app checks a landing before recording) | `app.py:9929`; gather `:766-779` | holds for the form; incomplete — F1 |
| Pre-ruling 3 (one project-relative text end to end) | `GatherOutcome.active_document` str; `_disk_problem(name=)`, `_active_document_missing`, `_reopen_active_document` all name `text` | holds (see §R20) |
| Pre-ruling 4 (writer refuses a sub-folder `files` key unless it is the document) | `manifest_writer.py:416-427` (D-B4: decided before the walk) | holds |
| Pre-ruling 5 / R1 (rows `new` / `keep` only; `PlannedFile.home`, `source: Optional`) | `project_gather_service.py:1051-1090`; `app.py:10433-10467` | holds |
| Pre-ruling 6 (codes) / P5 (`null` = absent) | `_parse_manifest_active_document` | holds |
| Pre-ruling 7 + R2/R3/R5/R8 refined/R10/R15 (carry, drop, keep) | `app.py:9539-9600`, `:9929-9950`, `:10006-10022`; `_DOCUMENT_DROP_OUTCOMES` | holds; same-file overlap — F2 |
| Pre-ruling 8 / R9 (≥1 entry for pasted only) | `app.py:10439` (`document.entries`), file-backed at any count | holds (TC-29 zero-entries arms) |
| Pre-ruling 10 (`_parsed_paste_text`, in `_SESSION_SNAPSHOT_NAMES`) | `app.py:2007`, `:3925`, reset `:10938` | holds |
| Pre-ruling 11 (reopen between A2L parse and install, A2L context) | `_handle_load_project` order: reset → manifest → check → A2L (`a2l_context`) → install set → `_reopen_active_document` → install | holds; Q5 end to end |
| Pre-ruling 12 / R7 (`_missing_recorded` primary data suffixes) | `variant_execution_service.py:2122-2134` | holds (M-38 KILLED) |
| R4 / R10 / R16 / R17 / R19 (one classifier, caps, catch set, file-level codes, wording) | `app.py` `recorded_document_state` `:1815-1915`, `_DOCUMENT_REASON` | holds; catch tuple redundancy — F7; R16 next step by text — F5 |
| R6 (user terms; class names to the log) | `safe_text` on every document line `:10207`; log-only `detail` | holds for the document lines; writer toast — F1 / F9 |
| R11 / R18 (one gather classifier, unresolved inside test, `lstat` source, folders up to the work-area root) | `project_gather_service.py:229-356` (D-B1, D-B2) | holds; the save can still be refused through F1 |
| R12 (bind spelled unresolved) | `app.py:10178`; reopen `:11326` | holds (M-I2 / R-32 KILLED) |
| R13 (`gathered` carried for a merge only) | `app.py:9957-9967` | holds (M-I1 KILLED) |
| Integration rulings 1–3 (next step by reason, merge row only with `project.json`, refused document = one `not readable`) | `variant_execution_service.py:1712`, `:1952-1958`, `:1125-1131`; `project_gather_service.py:1083-1089` | hold; ruling 1's mechanism — F5 |

Deviations accepted as justified: D-1 (`panel._dirty` read until Inc 10's public reader), D-2 (the dropped value named by its clipped JSON text), D-3 (no source to the gather without a plan row), D-B1…D-B5, D-E4-1/-2.

## §R20 dependencies (not a finding; the ruling is pending)

R20 relabels the problem row of a refused or unreadable `active_document` as `change document <text>`. **Four producers name that document today and must change together**, or one file becomes two rows:
- `manifest_writer._disk_problem(name=manifest.active_document)` via `check_project_files` (`manifest_writer.py:1266-1276`);
- `manifest_writer._active_document_missing` (`:1171-1211`);
- `app._reopen_active_document` (`app.py:11322-11324`);
- `variant_execution_service.manifest_problems` (`:1952-1960`, the refused value's `_ISSUE_ENTRY`).

D-B5 (one `could not be read` row for a held document) depends on `merge_load_problems` merging the check's row with the reopen's row by equal file text. Relabelling only the reopen and the reader splits a held, changed or missing document into two rows. Ruling 3's refused-key skip (`variant_execution_service.py:1125-1131`) keys on the raw text and is unaffected by the label. Tests that pin the current label: `test_tc_b100_30_refused_record_is_one_not_readable_row_and_no_reopen` (`firmware.s19`), `test_tc_b100_30_linked_document_is_one_not_readable_row` (file and full detail), `test_tc_b100_30_held_document_is_not_readable_and_stays_recorded`, the PC25 nodes naming the project text. F5's text lookup is also on R20's path.

## Inc 7 corrective pass 2 — round 3 (tag `inc7-cp2`)

Checked on the code (state `executed` where noted; the cp2 bytes are inside this diff's base and run in `green-01` / `guards-01`):

- **SEC7-R2-1, exact-text cache.** `_EntryWalk.check` keys children by the component's exact text, with one child dict per node and the `Path` cached beside it. `sub` and `SUB` are two nodes. A file node reused as a folder by a later entry reads `NotADirectoryError` → `missing`, which is safe. Sound.
- **R2-2, ceiling.** Only a new FOLDER component (not the last) counts toward `MANIFEST_FOLDER_CHECK_CAP`; the file an entry ends on is always checked; past the ceiling → `unchecked`, counted and folded. 8a parses `active_document` first in both the reader and `serialize_manifest`, so its walk is never past the ceiling and never silently `unchecked` (D-E4-2 probe). Sound.
- **SEC7-R2-2, one walk per serialize.** `walk = _EntryWalk(project_root)` once; `_reject_unsafe_entry(…, walk)` requires it; the 8a document check uses the same walk. `_resolve_intended_entries` is lexical (`os.path.normpath`), matching the walk's `pop` of `..`. Sound. (`intended_files` / `intended_derived` still `resolve()` per key. That predates cp2 and is outside its scope: no finding.)
- **SEC7-R2-3, SEC7-2 message.** The detection message names where `project.json` landed; the class rides in `details["exception"]` and the app logs it (`app.py:10716-10723`). The module stays headless. The other message in the same function still paints the class — **F9 (LOW)**.
- **SEC7-R2-4, kept-copy rollback.** The copy travels in `kept_copies`, never `placed_files`. All five rollbacks after the keep pass it (`app.py:10059, 10083, 10096, 10121, 10135`); the refusal before any copy exists (`:9997-10004`) correctly passes none. `_abort_save` removes a copy only when `project.json` reads back as the previous bytes, else names it. 8a's R5 path reuses this unchanged. Sound.
- **R2-1** was a test (TC-B100-07 refusal node); cp2 mutant KILLED per `increment-007.md`.
- **Deferred runs from Inc 7 §"Not run":** `guards-01` (75 passed, 29 snapshots) ran on a tree containing the cp2 bytes, so "guards on the final app bytes" is discharged as a superset. The reverse census stays not run by operator ruling. The security probe re-run belongs to `security-reviewer`.

## Re-pins (each checked against a requirement)

- RP-2 `test_b100_reuse.py` 7 → 8 placement calls, plus exactly one in `_write_editor_document` naming `workarea_root`: LLR-170.2 / R1 / SEC-1. Justified and stronger than before.
- RP-3, RP-5 (`test_b100_save_image.py`): the document is in the tree and in the plan rows (LLR-170.2, LLR-167.6). Justified.
- RP-4: `stat` import allowed, plus an explicit "no module name contains change" assertion that keeps the stated intent. Justified.
- RP-I1: superseded by integration ruling 3; will move again under R20 (§R20).
- RP-I2: `EXPECTED_SCANNED_TEST_FILES` 224 → 225 for the one new module, with the history line. Justified.

## Evidence checklist

- [x] **Diff read in full:** the 4 sources (`git diff dc3b314`, 1 071 lines for `app.py`, plus the three services), with the context functions listed in §Scope.
- [x] **Correctness pass:** the device-stem path (Q6, F1); the same-file overlap (Q1, Q3, F2); the copied-but-unrecorded wording (Q2, F3); the plan keys on failure (Q4, F4); the natural round trip (Q5, holds); by reading: reopen order and reset, bind spelling, `kept_copies`, walk ceiling vs document-first order, reader/writer symmetry of the `files` key.
- [x] **Simplicity pass:** the design's single classifiers (`recorded_document_state`, `classify_active_document`) are proportionate; nothing speculative. Duplicated `lstat` helpers — F7.
- [x] **Reuse:** the document write reuses `write_change_document` + `place_into_workarea` (the same serializer as the plan digest, so plan = landing); the gather reuses `_path_traverses_reparse_point`. Two new identical `_plain_entry` copies — F7.
- [x] **Tests reviewed for intent:** sampled kills are behavioural; three arms do not reach their target (F6); the next-step test pins the composer, not the cross-module spelling (F5).
- [x] **Verdict explicit:** `BLOCK — BLOCK-UNTIL: F1`. No HIGH.

## §4b `Independent review` cell (for the orchestrator to write)

`code-reviewer` · **BLOCK — BLOCK-UNTIL: F1** (0 HIGH, 1 MAJOR, 4 MINOR, 4 LOW).

- **F1 (MAJOR, design-gap) — open, blocks:** a change document with a device stem (`aux.json`, `con.json`, …) makes every Save project fail ("project.json was not written"). The app pre-checks with `is_active_document_form`; the writer also refuses device names. Fix: add the text-only key-mode refusal to the one predicate; arm Q6 + form arms; mutant drop-the-clause. Discharge: re-read and re-run Q6.
- **F2, F3 (MINOR):** wrong or contradictory document lines (same file both "not recorded" and "stays recorded"; "could not be placed" for a copied file). **F4 (LOW, design-gap):** plan keys list `active_document` when the document write fails. **F5 (MINOR):** next step looked up by reason text across three modules (on R20's path). **F6 (MINOR):** the R-19, R-17 (Load) and M-15 arms do not reach their target. **F7, F8 (LOW):** duplicated `lstat` helpers, redundant catch tuple, stale docstrings.
- **Inc 7 cp2 (round 3):** the cp2 fixes are sound; **F9 (LOW)**: the first containment toast still shows the exception class.
- Experiment E5: the code matches the approved design; impl-only defects F3, F5–F8; design gaps the review missed F1, F2, F4.

## Round 2

| Field | Value |
|---|---|
| Reviewer | `code-reviewer`, round 2. I am a different instance from round 1 and independent of the corrective-pass author. |
| Tree reviewed | Same worktree, still uncommitted, after corrective pass 1 (`experiment-8a/E5-cp1-notes.md`). Source sha256 (16): `app.py` `ebc6dbf4d1b6aa98`, `manifest_writer.py` `254693df5dcdf38a`, `variant_execution_service.py` `699c38bd2cce77cd`, `project_gather_service.py` `bd6f926590c17abd`. These equal the hashes in the cp1 notes. I diffed the tree against the pre-pass snapshot `…\scratchpad\cp8a-1\pre\s19_app\tui\`, whose hashes equal round 1's. Changed lines: `app.py` 244, `manifest_writer.py` 78, `project_gather_service.py` 42, `variant_execution_service.py` 147. I read all of them. I did not edit source or tests. |
| What I executed (state `executed`) | <ul><li>Round 1's probe file, unedited (`evidence/inc-8a/review/probes-r8a-round2-q1-q6.txt`): **7 passed, 1 failed (Q4)**. See F4.</li><li>The cp1 arms of `test_b100_document.py`: 24 passed, inside a combined run of 32 passed plus the Q4 failure.</li><li>The re-pinned R20 / F6 / SEC8a-5 nodes: `classifier_outcome`, `refused_record…`, `held_document…`, `test_tc_b100_07_rollback…`, and the document nodes of `test_b100_project_check.py`. 31 passed.</li><li>Two new probes, `evidence/inc-8a/review/test_r8a_round2_probes.py` (`probes-r8a-round2-cp1.txt`): **4 passed**.</li></ul>Setup: s19env 3.11, cwd = worktree, `PYTHONPATH` = worktree, `NO_COLOR` unset, `-p no:cacheprovider`. I ran no full suite and no mutants; I read the cp1 mutant table but did not re-run it. |
| **Verdict** | **PASS-WITH-NOTES.** F1 is closed, both on the diff and by the Q6 re-run. The pass introduced no MAJOR or HIGH. There are two new LOW notes (R2-1, R2-2); neither blocks. |

### Per-finding status

| id | Status | Basis |
|---|---|---|
| **F1** (MAJOR) | **closed** | The fix has two halves, and both are required. Without the gather half, Q6 still failed through `gathered`, as the cp1 notes say.<ul><li>**Form predicate.** `is_active_document_form` now ends with `and _manifest_key_refusal(text) is None`, and it also refuses `Cf` characters. The check is text only (no filesystem call), and the predicate stays total.</li><li>**Gather.** When the key mode refuses a copied row's project-relative text, the gather no longer appends that row to `gathered_rows`. The writer's `gathered` walk therefore cannot refuse the save through the same name. The gather still builds the document text, which then fails the form at the app, so nothing is recorded.</li></ul>**Q6 re-run**, for both `aux.json` and `con.json`:<ul><li>The status says "Saved project to …".</li><li>`patches/<name>` is copied into the tree.</li><li>One line: "was copied into the project's patches folder but is not recorded — its name is not one project.json records".</li><li>No `active_document`.</li></ul>The form arm covers `patches/aux.json`, `checks/CON.json`, `patches/nul.JSON`, `com1` and `lpt9`, plus 4 format characters, in the form, the writer and the reader. |
| F2 (MINOR) | closed | `_unrecorded_document_lines`: when the session document has the same project-relative text as the carried record, there is no "not recorded" line. Either the carried line stands alone (Q1), or there is one "stays recorded in project.json as it was" line (Q3). Q1 and Q3 pass. |
| F3 (MINOR) | closed | The "copied but not named" wording is keyed on the plan row plus `GATHER_DOCUMENT_NOT_RECORDED`. A document already in its home with an out-of-form name gets a line that names the name as the reason. Q2 and both cp1 arms pass. |
| F4 (LOW) | **closed by the correction (accepted; no objection)** | See §F4 below. Q4 still fails as written, by construction. |
| F5 (MINOR) | closed | The next step is now data: `ProjectFileProblem.step` holds a `STEP_*` mark, and `_next_step` reads only that mark. The reason strings and next-step texts are defined once (`variant_execution_service.py:206-221`), and the app and the writer import them. `grep` finds no other literal copy in the four sources. |
| F6 (MINOR) | closed | `V1_DOCUMENT` carries `"entries": []`. The R-17 Load arm (held document, no `files` record) and the M-15 arm exist and pass. The cp1 mutant table records R-19, R-17 and M-15 as KILLED (read, not re-run). |
| F7 (LOW) | closed | One `_plain_entry` remains, in the reader module; the two 8a copies are removed. `_DOCUMENT_PARSE_ERRORS = (ValueError, RecursionError, TypeError)`. `app._is_link_stat` and the older `lstat` helpers remain, which round 1 allowed as backlog. |
| F8 (LOW) | closed | Both docstrings now match the code. |
| F9 (LOW) | closed | The first containment message of `write_project_manifest` no longer paints the exception class. The class rides in `details["exception"]`, and `_write_and_verify_manifest` logs it (`app.py:10885-10893`). |

### F4: is the `_plan_without_document_key` correction real?

**Yes, as far as the plan object goes, and I accept it as discharging F4.** I checked these facts on the code:

- **No production code reads `plan.manifest_keys`.**
  - After `plan_project_save` returns, the app reads only `plan.rows`, `plan.refusal`, `plan.target_kind` and `plan.image`.
  - The written keys come from `recorded_document` and the inputs of `_save_manifest_keys`, never from `plan.manifest_keys`. A `grep manifest_keys` over `s19_app/tui` finds only the producer, the dataclass and the settle step.
  - The Save dialog does not paint the key list.
- **The only observer is the requirement's assertion, and the settled plan meets it.**
  - The settle step runs exactly when the commit step has decided `recorded_document is None` while the predicted keys hold `active_document`.
  - It removes only that key and keeps the order. On every path that reaches the write, the settled plan therefore equals the written key tuple.
  - The reverse mismatch (the written keys hold `active_document`, the plan does not) cannot occur. The carried value is classified before the plan, and the plan includes the key whenever a carried value remains.
- **Why Q4 still fails.**
  - LLR-167.6's threshold reads "`manifest_keys` holding `active_document` exactly when the write records it". The settled plan meets that.
  - Q4 spies the pre-write prediction. That prediction cannot meet the threshold, because a write that fails after the folder exists cannot be predicted before it.
- **Conclusion.** I found no concrete scenario where the settled plan and the written keys differ. The correction amounts to round 1's "recorded deviation" alternative, with an executable arm added.

### New findings

| id | Severity | Tag | file:line | Finding | Evidence | Fix |
|---|---|---|---|---|---|---|
| R2-1 | LOW (an unexplained silent outcome, though strictly better than before, when the whole save failed) | impl | `project_gather_service.py:749-752` | **The F1 gather guard applies to every gathered row, not only the document.**<ul><li>Example: a flow named `con.json` in the common `flows` folder. The gather now copies it into the project and leaves it out of `gathered`, with no status line. Before cp1, the writer refused the whole save.</li><li>Only the change document gets a line (`GATHER_DOCUMENT_NOT_RECORDED`).</li><li>The next Load does not report the orphan copy either: its "not recorded" scan covers top-level files only.</li></ul> | code read (no probe) | Either skip copying a row the key mode refuses (decide before the copy, with one finding naming the row), or emit one finding per unlisted row so the status names it. Backlog is enough; record it with Inc 8b's sub-folder work. |
| R2-2 | LOW (wording consistency) | impl | `app.py` commit step: the pasted arm's SEC8a-3 line vs the default branch of `_unrecorded_document_lines` | **A file-backed document whose home is a junction gets the generic reason.**<ul><li>Probe R2-P2: `P/patches` is a junction to `Q/patches`, and the document is `boost.json` from the common patches folder.</li><li>The save completes, Q is unchanged, and there is no `active_document`. There is also no plan row, so the containment pre-check works for the `outside` arm too.</li><li>The line reads "…was not recorded in the project — it could not be placed in the project's patches folder".</li><li>The pasted arm names the cause instead: "the project's patches folder is a link or is outside the work area". The file-backed line is true but less specific.</li></ul> | `probes-r8a-round2-cp1.txt` (R2-P2 passes) | When `_document_home_contained` refuses the home, pass that fact to `_unrecorded_document_lines` and reuse the pasted arm's reason. Optional. |

### Changes introduced by the pass, checked for MAJOR/HIGH (none found)

- **R20 relabel (4 producers) and step marks: sound.**
  - All four producers label the document through `document_problem_file(text)`: `_disk_problem(name=)`, `_active_document_missing`, `_reopen_active_document` and `manifest_problems`.
  - For a held document, the check's io_error row and the reopen's io_error row carry the same reason and the same `STEP_CHECK_THEN_LOAD`. `merge_load_problems` therefore still yields one row (`held_document_is_not_readable_and_stays_recorded` passes).
  - A refused key gets `DOCUMENT_REASON_OUT_OF_FORM` (or the link reason) and no step. It paints the kind's next step, "replace the file, or Save project to drop it", which is what Save project does for it (R5).
  - `DOCUMENT_NEXT_STEP[problem.step]` would raise on an unknown mark, but only the two constants are ever set.
- **`_unrecorded_document_lines`: sound.**
  - It compares unresolved `abspath` text, consistent with SEC8a-1.
  - I found one wrong-reason path, and it needs a race: the carried record classifies as readable, then the plan's digest fails. The line would then name the file's name as the reason instead of the failed read. I do not report it.
- **`_document_home_contained`: sound.**
  - It runs the guarded write's own `_guarded_destination` before a pasted or `outside` row is planned.
  - `in_home` skips the check, because its home is already `lstat`-checked as a plain folder.
  - R2-P2 confirms that the `outside` arm gets no row and the save completes.
  - A refused save returns before the commit step, so the SEC8a-3 line cannot paint on it.
- **SEC8a-1 (exact-text project compare, no `normcase`): no regression in outcome.**
  - Risk: on a case-insensitive host, the project's own document can be reopened by a path spelled in another case. `resolve_input_path` keeps an existing absolute path exactly as typed.
  - Probe R2-P1 tried a lower-case drive letter and a lower-case project folder.
  - Result: the document classifies `outside`. The plan predicts its landing as `patches/boost.json` with action `keep` (placement predicts the byte-identical reuse). The gather reuses the same file, `active_document` stays `patches/boost.json`, the patches tree is unchanged, and the save completes.
  - On that path `gathered` now lists `patches/boost.json`, which is harmless.
- **`_restore_manifest(already_kept=)`: sound.**
  - `already_kept` is True only when a kept copy beside that `project.json` holds exactly the previous bytes. The restore then logs one line instead of writing a second copy.
  - `_abort_save`'s later loop still names the copy whenever `project.json` does not read back as the previous bytes, so the user always gets a pointer to it.
  - A path-spelling mismatch can only make `already_kept` False. That gives the pre-pass behaviour: a second copy.

### §4b `Independent review` cell, round 2 (for the orchestrator to write)

`code-reviewer` round 2 · **PASS-WITH-NOTES** (0 HIGH, 0 MAJOR, 0 MINOR open; 2 new LOW).
- **F1 closed.** The form predicate and the gather's `gathered` guard together close it; the Q6 re-run saves with both device stems.
- **F2, F3, F5, F6, F7, F8, F9 closed.**
- **F4 closed by the settle step** (`_plan_without_document_key`). No production code reads `manifest_keys`, and the settled plan equals the written keys on every path. Q4 fails as written only because it spies the pre-write prediction.
- **New LOW R2-1:** the gather guard silently leaves any device-stem row out of `gathered`, not only the document, and paints no status line for the others.
- **New LOW R2-2:** a file-backed document with a junctioned home gets the generic "could not be placed" reason.
- **Probes:** `evidence/inc-8a/review/probes-r8a-round2-q1-q6.txt`, `probes-r8a-round2-cp1.txt`; source `test_r8a_round2_probes.py`.
