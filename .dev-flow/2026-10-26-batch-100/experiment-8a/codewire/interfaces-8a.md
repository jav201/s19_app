# Inc 8a — shared interfaces (fixed by the orchestrator for E2)

The three E2 agents prototype against these. An agent that needs a change writes it under "Proposed changes" at the end of its own prototype file; it does not change the interface on its own. E3 decides.

## variant_execution_service.py (group C owns)

- `KNOWN_MANIFEST_KEYS` gains `"active_document"`.
- `ProjectManifest.active_document: Optional[str]` — the project-relative POSIX text exactly as written in `project.json` (e.g. `"patches/boost.json"`); `None` when the key is absent or refused (a refusal adds one issue).
- `is_active_document_form(text: str) -> bool` (NEW, the one form predicate, S-11): True only for a relative POSIX path of exactly two components, the first a document home (`document_home_for_kind` values), the second ending `.json`, no `..`, no drive, no backslash, within `MANIFEST_ENTRY_MAX_CHARS`. Used by the reader and by `manifest_writer` (writer side).
- The `files` key equal to the accepted `active_document` is accepted by the reader; any other key under a document home is refused (LLR-169.4).

## manifest_writer.py (group B owns)

- `serialize_manifest(..., active_document: Optional[str] = None)` — emits `"active_document"` only when set; refuses (finding, nothing written) when `is_active_document_form` is False or `_reject_unsafe_entry` refuses it.
- `write_project_manifest(..., active_document: Optional[str] = None)` — passes it through.
- `verify_written_manifest(..., active_document: Optional[str] = None)` — `"active_document"` in the drift domain.
- `project_file_records(project_dir, active_document: Optional[str] = None)` — adds the document's record when the file exists; no record when absent.
- `check_project_files(...)` — the ONLY owner of `missing` for a recorded `active_document` (LLR-169.5 / LLR-170.3).

## project_gather_service.py (group B owns)

- ~~`GatherOutcome.active_document: Optional[Path]` — the landed document's absolute path~~ **SUPERSEDED by pre-ruling 3 (A3R2-9):** `GatherOutcome.active_document: Optional[str]`, the project-relative POSIX text of the landed document (written this save, or already in its home), `None` when no document or not placed.
- `plan_project_save(...)` gains the document row: landing under the kind's home, action ~~`new` / `replace` / `keep` (LED .72 Q3)~~ **`new` / `keep` only (E3 R1 supersedes `replace`, A3R2-9)**, decided through `classify_active_document` (E3 R11), and the merge `project.json` row `merge`.

## app.py (group A owns)

- Consumes all of the above; owns the write of a no-file document, binding it to the landing (LED .72 Q1), the panel flag (Q2), `_manifest_carry` of `active_document`, and the reopen in `_handle_load_project` (after the A2L, with `a2l_context`, never re-applying entries — Q6).

## E3 pre-rulings (orchestrator, 2026-10-30, after the three E2 prototypes)

These amend the interfaces above; the E3 reviewers review the design with them in place.

1. **Form predicate.** `ACTIVE_DOCUMENT_HOMES = frozenset({"patches", "checks"})` lives in `variant_execution_service.py` (no import of `project_gather_service`: import cycle, C-P1 / B-P2); a test pins it equal to the gather's homes. `is_active_document_form` is total (non-str → False, never raises, C-P3). The home component must match exactly (the app writes lowercase); the `.json` suffix is compared case-insensitively (C-P2). _Note (E3 R6): the predicate also refuses any C0/C1 control character, at both ends._
2. **The app checks a landing before it records it** (A-R6 / B-P-B1 / C-R1). If the landed document's project-relative text fails `is_active_document_form`, Save project still completes, records no `active_document`, and writes one status line naming the document. The manifest is never refused because of the document.
3. **One form end to end.** `GatherOutcome.active_document: Optional[str]` — project-relative POSIX text (B-P1). The document's `ProjectFileProblem.file` is that same text in `check_project_files` and in the reopen (A-P2 / C-R2), so `merge_load_problems` keeps one problem per file.
4. **Writer/reader symmetry.** The writer refuses a sub-folder `files` key unless it equals `active_document` (B-P3).
5. **Plan rows.** `PlannedFile.home: Optional[str]`, `source: Optional[Path]` (None for a pasted document), role `"document"`, actions `new` / `keep` (`replace` withdrawn by E3 R1), merge `project.json` row `merge` (A-P1 / B-P4).
6. **Issue codes** (C-P4): non-string / empty / out-of-form → `MANIFEST-BAD-STRUCTURE`; escape-type rules and a link or junction → `MANIFEST-PATH-ESCAPE`. Explicit `"active_document": null` reads as absent, 0 issues (C-P5).
7. **Carry when the session has no document** (A-R12): a save into the open project, like a merge, carries the target's `active_document`; it is dropped only when the target's record is refused by the reader. A record whose file is missing is carried as recorded and reported `missing` on Load (B-R9) — never silently dropped. _Note (E3 R2, R3, R5): Save project drops a carried record whose file is absent, with one status line; a session document that was not placed counts as no session document; a refused target value is a skipped entry and Save project keeps `project.json.previous-<UTC>`, the status naming the copy and the dropped value. Note (E3 R8 refined, R10): Save project drops a carried record only when the one document classifier says `missing`, `link` or `unreadable`, and keeps it for `too_large` and `io_error`._
8. **Gather scope** (A-R10): the ≥1-entry rule applies only to a pasted (no-file) document; a file-backed document is gathered as today.
9. **In-place `replace`** (A-R5 / A-R7): the document rewrite in its home uses the staged replace with the same containment and reparse checks as the placements; the rollback restores the previous bytes from a separate restore list (A-R8), never deletes a pre-existing user file (B-R7). In a merge the target's own document file is never rewritten (LLR-164.2). **SUPERSEDED by E3 R1: there is no in-place `replace`; Save project never overwrites an existing project file.**
10. **Unparsed paste buffer** (A-R4): `_parsed_paste_text` in `app.py` is accepted (same file, no fifth source).
11. **Reopen point:** between the A2L parse and the install loop (A's C4 answer), with the A2L context; the TOCTOU gap between the read's walk and the reopen (C-R3) is the same class as Inc 7's images — recorded, not fixed at 8a.
12. **`_missing_recorded`** restricted to primary data suffixes joins 8a (C-R6, same file). Undo depth after the reopen (A-R14) → backlog.

## E3 round-1 rulings applied

Source: `../E3-rulings.md` (2026-10-30). The three prototype files and the requirements follow these lines; a ruling wins over an earlier line above.

- **R1** No in-place rewrite of an existing project file: a pasted document is written as a NEW file through the normal placement (then bound); a file-backed document already in the target's home is recorded as on disk (`keep`, flag and one status line kept if edits are unsaved); a file-backed document outside the project is copied (`new`). Document-row actions are `new` / `keep` only. **Pre-ruling 9 and LED .72 Q3 (`replace`) are superseded by R1.**
- **R2** Save project (open project or merge) drops a carried `active_document` whose file is absent and writes one status line naming it; the four carry writers still carry it as recorded.
- **R3** A session document that was not placed (write failed, gather refused it, landing failed the form) counts as no session document: the target's `active_document` is carried (pre-ruling 7), plus the one status line about the document.
- **R4** The reopen checks a 1 MiB byte cap and a 1 000-entry cap before parsing; over either cap: 1 `not readable` ("too large to reopen"), the project still loads, Load and panel under 1 s.
- **R5** A refused `active_document` in a Save project target is a skipped entry: `project.json.previous-<UTC>` is kept and the status names the copy and the dropped value (amends pre-ruling 7).
- **R6** Painted text about the document is in user terms (reader messages, issue codes, exception class names go to the log only); `is_active_document_form` refuses C0/C1 control characters (amends pre-ruling 1).
- **R7** `_missing_recorded` restricted to primary data suffixes (pre-ruling 12) has its requirement arm in LLR-169.5.
- **Types after the pass:** `GatherOutcome.active_document: Optional[str]`; `PlannedFile.home: Optional[str]`; plan actions `new` / `keep` for the document row.

## E3 round-2 rulings applied

Source: `../E3-rulings.md` "E3 round 2 — orchestrator rulings" (2026-10-30). A ruling here wins over an earlier line above.

- **R8 (refined)** Save project drops a carried `active_document` only on `missing`, `link` or `unreadable` (one status line), and keeps it on `too_large` and `io_error`; on Load all four non-`ok`, non-`missing` outcomes paint `not readable` with the reason in user terms.
- **R9** The ≥1-entry rule applies to a pasted document only; a file-backed document is gathered and recorded whatever its entry count (pre-ruling 8; now also in HLR-170 / LLR-170.2).
- **R10** One document classifier in `app.py`, `recorded_document_state(project_dir, text, a2l_context=None) -> RecordedDocumentState` (`ok` with the parsed document, `missing`, `link`, `too_large`, `unreadable`, `io_error`): two `lstat`, 1 MiB cap, one bounded read, guarded decode and 1 000-entry count, parse of the same bytes; used by the reopen and by Save project.
- **R11** One gather classifier in `project_gather_service.py`, `classify_active_document(project_dir, source, home) -> (kind, name)` (`in_home` → `keep`; `outside` → `new` / `keep`, copied; `inside_elsewhere` and `missing` → 0 rows, nothing copied, one status line); "inside" on the unresolved text, the source `lstat`-ed (a link is never copied); used by the planner, the gather and the app's plan; the save is never refused because of the document.
- **R12** The bind stores the unresolved `project_dir / home / name`, never `PlacementResult.path`.
- **R13** `gathered` is carried for a merge only, never for an open-project save.
- **R14** Requirement text: HLR-170, LLR-170.2, LLR-164.2, LLR-170.3 (and LLR-167.6 for A3R2-1) amended; ledger LED .74.
- **Types after round 2:** `PlannedFile.source: Optional[Path]` (None for a pasted document); `PlannedFile.role` gains "document"; new `RecordedDocumentState` (app); `ChangeService.load` is no longer called by the reopen.
