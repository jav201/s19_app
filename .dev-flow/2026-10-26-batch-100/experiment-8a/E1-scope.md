# E1 — Inc 8a requirements scope and E2 slice

Step E1 of `PLAN.md`. Source: `01-requirements.md` after the E1 edits (LED-2026-10-26-batch-100.72). Line numbers are those of the edited file.

**Counts:** 1 HLR · 11 LLRs (4 full at 8a, 7 partial arms) · 2 ATs · 11 TCs. LLR-178.1 had its wording clarified for OBS-7-1. It is not owed at 8a.

## 1 · Scope list

EARS types: **U** = ubiquitous, **E** = event-driven ("When …"), **UW** = unwanted ("If …, then …"). A requirement marked **E+UW** has one "shall" whose outcome set includes the failure path.

| Id (line) | 8a share | One-line statement | EARS | Threshold (8a arm) | Negative control (8a) |
|---|---|---|---|---|---|
| HLR-170 (479) | full | Save project places the editor's document and records `active_document`; Load reopens it; a bad, missing or unwritable document is listed or named, and the load or save continues | E, E, UW, UW | `p06` A reopened with 1 entry; `p01` → `changes.json` reopened; clash → `changes_1.json`; missing → 1 problem; failed write → saved, no key, 1 status line | base `1d677ba` RED (P-8) |
| LLR-170.1 (1015) | full | `active_document` holds one `patches/`\|`checks/` `.json` project-relative path, with one predicate at the writer and the reader; it is a known key | U | 2 round-trips; 6 reader issues / 6 `None`; 2 writer refusals; absent → no key; carried by a variant append | skip reader prefix rule; drop writer check; key left out of `KNOWN_MANIFEST_KEYS` |
| LLR-170.2 (1025) | full | When Save project runs with a ≥1-entry document and no file, the app writes `changes.json` into the home for its kind (M-1) and the gather names the landing; a failed write or a later failure is handled | E+UW | 9 arms: change/check home, `_1`, reuse, file-backed byte-equal, 0 entries, failed write, rollback, 0 new imports | base RED; document left off placed files; key recorded after failed write |
| LLR-170.3 (1035) | full | When a project with an accepted `active_document` loads, the document goes through `ChangeService.load` with the A2L context after the A2L; if it cannot be read, 1 `not readable` and the load continues | E+UW | 1 entry and flag clear; 0 unresolved symbols; no-A2L load; missing → exactly 1 (`missing`, from LLR-169.5); `{` → exactly 1 `not readable`; 0 raises | base RED; load without `a2l_context` / before the A2L; double report |
| LLR-167.8 (875) | positive arm (LED .61) | When Save project completes after the app wrote the editor's document, the panel's dirty flag is cleared; refused, failed-write and file-backed-dirty saves keep it | E+UW | 4 arms: flag False with 0 `LoadGuardScreen`; refused → True; failed write → True; file-backed dirty → True | skip `mark_saved`; call it always |
| LLR-164.2 (715) | merge carry (B-06, LED .52 (b)) | The merge carries `gathered` (target + new rows) and `active_document` (carried, or the session's placed document) | U (decision table) | carried keys 0 changed; target document file 0 bytes changed | session `active_document` (`None`) passed in a merge |
| LLR-167.6 (855) | document row + merge (LED .63, B-06) | The plan names the document row and the merge rows; the handler writes exactly those | U | document row `new`/`keep`/`_1`, 0 rows when no document, merge `project.json` row `merge`; 0 differences; `manifest_keys` ∋ `active_document` iff written | handler places a file with no plan row |
| LLR-168.3 (905) | `active_document` carried (AT-B100-20) | The 4 in-project writers carry the keys they do not own | U | a recorded document still recorded after the append (TC-B100-20); AT-B100-20: 5 keys equal over 3 writers | seam call removed; absolute `batch` passed |
| LLR-169.2 (935) | active-document arm (A-15) | The seam's `files` covers the top-level data/A2L files and the active document | U | 5 keys (4 + `patches/boost.json`), `patches/other.json` absent; missing document → no record, 0 raises | active document left out → 4 keys |
| LLR-169.3 (945) | `active_document` drift arm | Verify includes `active_document` in its drift domain | U | 1 changed `active_document` → 1 mismatch | key left out of the domain |
| LLR-169.4 (955) | `files` key of the active document | The reader accepts the `files` key equal to the accepted `active_document` and refuses other sub-folder keys | U | 1 record / 0 issues; `patches/other.json` → 1 `MANIFEST-BAD-STRUCTURE` | accept any `patches/` key |
| LLR-169.5 (965) | missing-document owner | `check_project_files` reports a recorded `active_document` absent from disk as `missing` | U | 1 `missing`, with and without a `files` record (2 arms) | (new arm; mutant: skip the document → 0 problems) |

| AT / TC | Owner | 8a share |
|---|---|---|
| AT-B100-08 (HLR-170 acceptance; §5.3 row 1913) | US-160 | written at 8a: paste 1 entry → Save P → fresh app opens P → the ledger lists the address |
| AT-B100-20 (HLR-168 acceptance; §5.3 row 1925) | US-158 | `active_document` carried across variant append / MAC / A2L sync, then reopened in a fresh app |
| TC-B100-28 | LLR-170.1 (+ LLR-169.2 A-15 arm) | full |
| TC-B100-29 | LLR-170.2 | full |
| TC-B100-30 | LLR-170.3 | full |
| TC-B100-70 | LLR-167.8 | positive arm and the failed-write and file-backed arms; the Inc 5 "document not written" node is re-pinned (C5) |
| TC-B100-05 | LLR-164.2 | merge carry |
| TC-B100-59 | LLR-167.6 | document row, merge |
| TC-B100-20 | LLR-168.3 | `active_document` carry |
| TC-B100-22 | LLR-169.2 | active-document arm (runs in TC-B100-28) |
| TC-B100-23 | LLR-169.3 | `active_document` drift arm |
| TC-B100-24 | LLR-169.4 | active-document `files` key |
| TC-B100-25 | LLR-169.5 | missing-document arm |

## 2 · Inc 7 items routed to 8a

- **OBS-7-1** (`_relation_line` decides "in this project" from `files` only): **stays an observation**. There is no code change and no new requirement. LLR-178.1's wording now says the match is against a `files` record, because the composer is pure. Only a hand-made manifest reaches the case, and that manifest also shows `no digests saved`.
- **LED .70** (Inc 7's deferred cp2 verification): **for E5/E6, not a requirement.** It covers four runs. (1) The full 31-module reverse census on the final tree. (2) The guards and `-k census` on the final `app.py` bytes. (3) The security probes `probe_a_dos.py`, `probe_e_load.py` and `r2_probe_*`. (4) The round-3 code and security review of the cp2 diff. Schedule them with E6's single census, so they do not add a separate full-census launch.

## 3 · Slice for E2

Function names come from the requirements and the Code-Wire baseline (`codewire/baseline-notes.md`). **(guess)** marks a name or a change that the requirements imply but do not name.

### Existing nodes that change (15 functions + 3 data nodes)

| # | Node | File | What changes | Requirement |
|---|---|---|---|---|
| 1 | `_handle_save_dialog` | `app.py` | writes a no-file document (`write_change_document` into the kind's home), passes the landing to the gather, records `active_document`, handles failed-write status and rollback (placed files), clears the panel flag only on the written-document path, merge carry of `gathered` / `active_document` | 170.2, 167.8, 164.2, 167.6 |
| 2 | `_plan_project_save` | `app.py` | document bytes via `serialize_change_document` → digest and size as a plan input; merge target | 167.6 |
| 3 | `_save_manifest_keys` | `app.py` | `active_document` in the key list exactly when written | 167.6 |
| 4 | `_write_and_verify_manifest` | `app.py` | takes `active_document`; `files` over the active document too | 169.2, 170.1 |
| 5 | `_manifest_carry` | `app.py` | carries `active_document` as a project-relative POSIX string | 168.3 |
| 6 | `_handle_load_project` | `app.py` | reopens the document via `ChangeService.load(a2l_context=…)` after the A2L; adds `not readable` | 170.3 |
| 7 | `serialize_manifest` | `manifest_writer.py` | `active_document` parameter, emitted when set, form check plus `_reject_unsafe_entry` | 170.1 |
| 8 | `write_project_manifest` | `manifest_writer.py` | passes `active_document` through (guess: depends on its signature) | 170.1 |
| 9 | `verify_written_manifest` (and possibly `_resolve_intended_entries`, guess) | `manifest_writer.py` | `active_document` in the drift domain | 169.3 |
| 10 | `project_file_records` | `manifest_writer.py` | adds the active document's record; no record when it is absent | 169.2 |
| 11 | `check_project_files` | `manifest_writer.py` | `missing` for a recorded `active_document`, with or without a `files` record | 169.5 |
| 12 | `read_project_manifest` | `variant_execution_service.py` | parses `active_document` (1 issue + `None` when refused) | 170.1 |
| 13 | `_parse_manifest_files` / `_recorded_file` (guess: one of the two) | `variant_execution_service.py` | accepts the `files` key equal to the accepted `active_document` | 169.4 |
| 14 | `gather_project_artifacts` | `project_gather_service.py` | names an active document already in its home (C3) in the outcome | 170.2 |
| 15 | `plan_project_save` | `project_gather_service.py` | document row (landing under the home), merge `project.json` row `merge` | 167.6 |
| D1 | `KNOWN_MANIFEST_KEYS` | `variant_execution_service.py` | + `active_document` (C2) | 170.1 |
| D2 | `ProjectManifest` | `variant_execution_service.py` | + `active_document: Optional[Path]` | 170.1 |
| D3 | `GatherOutcome` | `project_gather_service.py` | + the landed active-document path (C3) | 170.2 |

The plan's document row may also need a role or home on `PlannedFile` / `SavePlanRow` (guess), because `predict_placement` today places every row at `target`.

### New nodes (4)

| # | Node | File | Purpose | Basis |
|---|---|---|---|---|
| N1 | `_parse_manifest_active_document` | `variant_execution_service.py` | the reader arm, by analogy with `_parse_manifest_derived_from` | implied by 170.1 (name: guess) |
| N2 | one form predicate for `active_document` (prefix plus `.json`) | `variant_execution_service.py` (imported by `manifest_writer`, the same way as `_resolve_manifest_entry`) | "one predicate at both ends" (S-11) | implied by 170.1 (name and home: guess) |
| N3 | `_write_editor_document` | `app.py` | write the no-file document and return the landing or failure | guess (may be inline in node 1) |
| N4 | `_reopen_active_document` | `app.py` | the reopen and its `not readable` problem | guess (may be inline in node 6) |

**Node count: 22.** That is 15 changed functions, 3 data nodes and 4 new functions. 20 are firm or implied; N3 and N4 are guesses. The count is above ~8, so E2 runs one agent per file group:

| Group | File | Nodes | # |
|---|---|---|---|
| G1 | `app.py` | 1–6, N3, N4 | 8 |
| G2 | `manifest_writer.py` | 7–11 | 5 |
| G3 | `variant_execution_service.py` | 12, 13, D1, D2, N1, N2 | 6 |
| G4 | `project_gather_service.py` | 14, 15, D3 | 3 |

Four files, at the cap, and they match §5.5 row 8a. `changes/io.py`, `change_service.py` and `screens_directionb.py` are called but not changed.

### Callees that stay unchanged (context for examples; not slice nodes)

`write_change_document`, `serialize_change_document` (`changes/io.py`), `ChangeService.load` / `mark_saved` (`change_service.py`), `PatchEditorPanel.mark_saved` (`screens_directionb.py`), `predict_placement`, `document_home_for_kind`, `_resolve_manifest_entry`, `_reject_unsafe_entry`, `merge_load_problems` (guess: unchanged if the load appends `not readable` the way it does for images), `manifest_rewrite_refusal`, `manifest_keep_reason`, `_reset_project_session`, `_load_a2l_data_with_cache`.

## 4 · Open questions for E3 (not decided in E1)

1. **Repeated saves of a pasted document.** After the first write, the editor's document still has no `source_path`. So a later Save project with edits writes `changes_1.json`, `changes_2.json` and so on, and `active_document` names the newest. Should the document be rebound to the landed file, or is the growth accepted? Rebinding would disable Edit-JSON and Undo for file-backed documents.
2. **Paste-buffer text that was never parsed** sets the dirty flag. A Save project that writes only the entries would clear the flag over that text (LLR-167.8). This follows `mark_saved`'s existing w3 semantics, but no requirement covers the buffer.
3. **`replace`** is listed among LLR-167.6's action words, but no requirement says which row produces it. The code comment says Inc 8a adds it.
4. **C4: reopen order.** `_step_a2l` / `_step_finalize` are deferred through `call_later`. Confirm that none of them resets the document after the reopen.
5. **Mutant feasibility (LLR-170.3).** The "load before the A2L" mutant fails only if the change service does not re-resolve symbols when the A2L attaches later. The "no `a2l_context`" mutant is the stronger control.
6. **Entry state on reopen.** The saved image already carries the entries, and no requirement says whether the reopened entries show as applied. US-160 asks only that they are listed.

## 5 · Observations (not changed, outside 8a's arms)

- LLR-168.3 has two "shall"s (written at Inc 6). Only its carry arm is owed at 8a, so it was not restructured.
- HLR-170 is a compound HLR of EARS clauses (E, E, UW, UW), each in its own sentence. It was kept as an HLR; the LLRs carry singular statements.
