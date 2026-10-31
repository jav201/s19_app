# E3 round 1 — orchestrator rulings (2026-10-30)

Inputs: `E3-architect.md` (FAIL, 5 MAJOR) and `E3-security.md` (FAIL, 4 MAJOR). These rulings amend `codewire/interfaces-8a.md` (its pre-rulings stay unless changed here) and drive one design-correction pass on the three prototype files and the requirements.

## R1 — No in-place rewrite of an existing project file (closes A3-4, S3-2, S3-3, S3-4, S3-5, S3-10; supersedes pre-ruling 9 and LED .72 Q3)

Save project never overwrites a file that already exists in the project. Prototype A's rule (b) ("rewrite a file-backed document already in the target's home") is withdrawn.
- A **pasted** document (no `source_path`, ≥1 entry) is written as a NEW file in its kind's home through the same placement as other files (immutable reuse, `_N` on a name clash with different bytes — LLR-155.3 holds unchanged, no exception). After the write the editor's document is bound to that landing (Q1 stays).
- A **file-backed** document already in the target's home is recorded as `active_document` as it is on disk (plan action `keep`); Save project does not write it. If the panel holds unsaved edits, the flag stays True and one status line says the change document has unsaved edits and names the Patch Editor save as the way to keep them.
- A **file-backed** document outside the project is copied by the gather as today (action `new`), on-disk bytes.
- The document row's actions are `new` and `keep` only; `replace` is not produced by the document row in 8a. LLR-167.6's LED .72 Q3 sentence is amended accordingly; LLR-170.2's Q1 sentence is amended: a second Save project of a bound document with edits writes nothing for the document, keeps the flag, 1 file under `patches/`.
- LLR-167.8's file-backed arm now holds on the natural path (Load P → edit → Save P → flag True).

## R2 — Carried document whose file is absent (A3-2)
The four carry writers (variant append, MAC sync, A2L sync, save-back) carry `active_document` as recorded. **Save project** (open-project save or merge) drops a carried `active_document` whose file is absent from disk and writes one status line naming it — that is the "Save project to drop it" recovery the panel token promises. Amend LLR-164.2's threshold to state it.

## R3 — Session document not placed (A3-3)
A session document that was not placed (write failed, gather refused it, landing failed the form) counts as "no session document": the target's `active_document` is carried (pre-ruling 7), plus the existing one status line about the document.

## R4 — Reopen bounds (S3-1)
The reopen checks, before parsing, a byte cap of 1 MiB and an entry cap of 1 000 (count after parse is acceptable only if the byte cap already bounds the parse time under 0.1 s — measure; otherwise a pre-parse count). Over either cap → 1 `not readable` ("too large to reopen"), the project still loads, Load + panel stay under 1 s. Amend LLR-170.3 with this arm and its mutant (cap removed → a 20 000-entry document takes > 1 s → RED).

## R5 — Refused `active_document` in a Save project target (S3-6)
A refused `active_document` in the target manifest is a skipped entry: Save project keeps `project.json.previous-<UTC>` (SEC7-3 path) and the status names the copy and the dropped value. Amend ruling 7's text.

## R6 — Painted text (S3-7)
Every painted reason about the document is in user terms; reader messages, issue codes and exception class names go to the log only. `is_active_document_form` also refuses C0/C1 control characters (amends pre-ruling 1). One example asserts 0 issue codes and 0 class names in the painted status and panel text for the document arms.

## R7 — `_missing_recorded` (A3-11)
Keep pre-ruling 12, with a requirement arm: LLR-169.5 gains "a missing variant id `boost` with a document `patches/boost.json` present → the missing problem names the variant's data file, never the document"; mutation dropping the suffix restriction → names `boost.json` → RED.

## Prototype edits (no ruling needed — apply as the reviewers wrote them)
A3-1 (one problem text `patches/boost.json` everywhere), A3-5 (the document write adds `P/patches/` and a fresh `P/` to `created_dirs`; rollback example), A3-6, A3-7, A3-8, A3-9 (one shared "in its home" test, the reader's predicate + the walk), A3-10 (`_parsed_paste_text` in `_SESSION_SNAPSHOT_NAMES`), A3-12 (build the recorded path from the home constant), A3-14, S3-8 (records walk the document's components), S3-9 (two `lstat` before the reopen, absolute path), S3-11 (writer checks the document first, emits it last), S3-12 (examples aligned to the rulings). A3-13 is record-only.

## After the design-correction pass (orchestrator, 2026-10-30)
- **R8 (R-16):** Save project also drops a carried `active_document` whose file is present but not readable (fails the reopen's caps or parse), with one status line — the "Save project to drop it" token then holds for both `missing` and `not readable`. The four carry writers still carry it as recorded.
- **R9 (R-10):** HLR-170's "at least 1 entry" applies to a pasted (no-file) document only; a file-backed document is gathered and recorded as today, whatever its entry count (pre-ruling 8). Not a deviation.
- Model note: the Sonnet design pass truncated `proto-8a-writer-gather.md` twice and rebuilt it from its own `cat -n` output; round 2 reads the whole file.

## E3 round 2 — orchestrator rulings (2026-10-30)
Inputs: `E3-architect.md` Round 2 (FAIL: A3R2-1, A3R2-2 MAJOR) and `E3-security.md` Round 2 (FAIL: S3R2-1, S3R2-3 MAJOR). All round-2 findings are accepted with the reviewers' fixes, with these rulings:

- **R10 — One document classifier for the reopen and Save project** (S3R2-1, S3R2-3, S3R2-4, A3R2-2). One pure function in `app.py` (or the reader, if it has no app state) reads the recorded document once, in this order: `lstat` of the home and the file (a link → `link`), size cap 1 MiB (→ `too_large`), one bounded read, guarded parse of THOSE bytes via the change-document text loader (catch `JSONDecodeError`, `RecursionError`, `UnicodeDecodeError`, `ValueError`, `TypeError` → `unreadable`), entry count only when `entries` is a list (> 1 000 → `too_large`; not a list → `unreadable`), OSError on read → `io_error`. Outcomes: `ok` (with the parsed document), `missing`, `link`, `too_large`, `unreadable`, `io_error`. The reopen uses the parsed document from the same bytes (no second read).
- **R8 refined (S3R2-2):** Save project drops a carried `active_document` only on `missing`, `link` or `unreadable` (a real file fault), with one status line; it KEEPS the record on `too_large` and `io_error` (the app's own large document, or a locked file, is never dropped). On Load, `too_large` / `unreadable` / `link` / `io_error` all paint `not readable` with the reason in user terms.
- **R11 — One gather classifier** (A3R2-1): `project_gather_service` classifies a file-backed document as `in_home` / `outside` / `inside_elsewhere` / `missing`, deciding "inside" on the UNRESOLVED text and `lstat`-ing the source (a link → no copy, one finding — S3R2-5). Planner and gather both use it: `in_home` → `keep` row; `outside` → `new` row, copied; `inside_elsewhere` and `missing` → 0 document rows, nothing copied, one status line. The save is never refused because of the document's digest or absence (regression at `app.py:9283-9300` avoided).
- **R12 — Bind spelling** (S3R2-6): the bind stores `project_dir / home / name` (unresolved), never `PlacementResult.path`.
- **R13 — `gathered` carry** (A3R2-4): `gathered` is carried for a merge only, never for an open-project save.
- **R14 — Requirement text** (A3R2-3): HLR-170 and LLR-170.2 state R3 (a not-placed session document → the target's record carried) and R9 (≥1 entry for pasted only; a file-backed document with 0 entries is recorded — give it an arm). LLR-164.2 gains R8-refined arms + mutant; LLR-170.3 gains the R10 exception arm (1 MiB of `[` → `not readable`, Load completes) + mutant. One ledger entry LED .74.
- Everything else as the reviewers wrote it: A3R2-5 (restore `PlannedFile.source: Optional[Path]` + role "document", and baseline's TC-B100-23 "holds" example — content lost in the Sonnet rebuild), A3R2-6, A3R2-7, A3R2-8, A3R2-9, S3R2-7, S3R2-8.

## E3 round 3 — design approved (PDR), addenda for E4 (orchestrator, 2026-10-30)
Round 3: architect PASS-WITH-NOTES (A3R3-1…5), security PASS-WITH-NOTES (S3R3-1…3); 0 HIGH, 0 MAJOR. The design is approved; these addenda are implemented and tested in E4 directly (no further design pass):
- **R15 (A3R3-1):** Save project classifies the carried record in step (1) but paints its drop / `io_error` line in the commit step, and only when the carried record is the one written to `project.json`; a placed session document that replaces it → 0 such lines. LLR-164.2 "1 status line for `io_error`" holds only for the carried-and-written case.
- **R16 (A3R3-2, S3R3-3):** one reason for `io_error` everywhere: `could not be read`, next step `check that the file can be opened, then Load again`. The `too_large` next step: `open it from the Patch Editor (it can take a while)`.
- **R17 (A3R3-3):** `recorded_document_state` step (5) marks `unreadable` only on the file-level codes `MF-JSON-PARSE`, `MF-BAD-STRUCTURE`, `CHG-V1-FORMAT`, `CHG-FORMAT`, `CHG-KIND-UNKNOWN`, `CHG-ENCODING-UNKNOWN`, `CHG-VALUE-MODE-UNKNOWN`; entry-level findings never make the document unreadable. Example: Save project (no A2L context) keeps a symbol-entry record; mutant "any ERROR → unreadable" → record dropped → RED.
- **R18 (S3R3-1):** the gather passes the UNRESOLVED source to `place_into_workarea`; `classify_active_document` also `lstat`s the source's parent folder when the source is under the work area (a link → `missing`, no copy, one line). Example: `P/patches` swapped for a junction to a private folder → Save into Q copies 0 bytes; mutant checking only the file → RED.
- **R19 (S3R3-2):** the classifier's catch set includes `ValueError` (a 5 000-digit integer); example + mutant. The `parse_change_document` "never raises" contract bug goes to BACKLOG-CODE (outside 8a).
- A3R3-4, A3R3-5: record only (R-16 resolved by LED .74 addendum + R16; the `P/patches`-is-a-file case is the same outcome under either class).

## E5 pre-ruling (orchestrator, 2026-10-30)
- **R20 (integration risk):** the problem row of a refused or unreadable `active_document` is labelled as the change document — file label `change document <text>` — so it never merges with a data file of the same name (`active_document: "firmware.s19"` must not paint `not readable firmware.s19` against an image that opened). Out-of-form reason: `the recorded change document path is not one the app can use`. Applied in the E5 corrective pass with the reviewers' findings.
