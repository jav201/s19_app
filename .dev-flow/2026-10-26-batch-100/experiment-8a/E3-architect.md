# E3 — architect review of the Inc 8a design (Code-Wire graph, no code)

Step E3 of `PLAN.md`. Reviewer: architect. Read-only toward the design; this file is the only write.

**Inputs read:** `PLAN.md`, `E1-scope.md`, `01-requirements.md` (HLR-170, LLR-170.1–170.3, LLR-167.6, LLR-167.8, LLR-164.2, LLR-168.3, LLR-169.2–169.5, AT-B100-08 / AT-B100-20 index rows), `codewire/baseline-8a.md`, `baseline-notes.md`, `proto-8a-app.md` (A), `proto-8a-writer-gather.md` (B), `proto-8a-reader.md` (C), `interfaces-8a.md` with its 12 E3 pre-rulings (R1–R12 below), `03-increments/increment-007.md` §5–§6. Source checks at `dc3b314` are cited `file:line`.

## Verdict

**FAIL** — 5 MAJOR findings open (A3-1 … A3-5). None needs code to see; each is a disagreement between two graph files, or between a pre-ruling and a requirement or an existing rule. Three need an orchestrator ruling (A3-2, A3-3, A3-4); two are prototype edits (A3-1, A3-5). Once they are settled, the remaining MINOR/LOW items are prototype text edits. The overall shape is sound: save order, load order, the reader-first parse order, the one walk, and the plan-then-execute seam all hold.

## What holds (evidence, not findings)

- **Save order** (A `[Data: ChangeDocument.source_path]` sequence): plan → document write in the rows loop → gather → manifest write and verify → bind and clear the flag in the commit block only. `_plan_row_mismatch` (`app.py:1666-1689`) accepts a `replace` row: it compares `reused` with `action == keep`, so `reused=False` matches `replace`. A replace row needs no change there. Only the refusal text says "new".
- **Plan digest = write bytes.** `serialize_change_document` is deterministic: it has no timestamp, writes entries in document order, and uses `indent=2` (`changes/io.py:1393-1449`). `write_change_document` serializes the same way (`:1504` ff.). So the plan's `keep` / `_1` prediction and the M-1 placement compare equal bytes.
- **Load order** (A finding C4): `current_file` is cleared by `_reset_project_session` (`app.py:10259`). The install re-renders the rows against the new ranges (`app.py:13509-13517`) and stamps `ChangeService.mark_saved` on the new image (`:13461-13462`). A reopen between `:10550` and `:10551` therefore survives the install and the deferred `_step_*` chain. The A2L payload is `parse_a2l_file`'s dict (`app.py:13926` ff.), the same shape that `flow_execution_service.py:445-485` passes as `a2l_context`. `ChangeService.load` takes `a2l_context` (`change_service.py:1538-1543`).
- **One problem per file** is keyed by `ProjectFileProblem.file` (`variant_execution_service.py:1606-1612`). `not readable` (2) outranks `changed on disk` (3) (`:1500-1508`). So a `{` file with a `files` record gives exactly 1 `not readable` **only if both producers use the same name** (see A3-1).
- **Reader** (C): parse order (text rules → form → walk, document first), the exact-text `files` exception, and the codes all match R6 and LLR-170.1's 6 reader arms. SEC6-2 is kept: a refused value is a skipped entry, so `manifest_rewrite_refusal` refuses the rewrite. Outside readers do not break (C table).
- **Writer** (B): the key is emitted last and only when set, so TC-B100-21 byte identity holds. There is one `_EntryWalk` per serialize (SEC7-R2-2). The refusal returns before staging (LLR-169.7). `project_file_records` adds at most one `lstat` and one hash, with no sub-folder listing (O-2).
- **Carry writers** (append, MAC, A2L sync, save-back) thread `active_document` through `_manifest_carry` → `_rewrite_project_manifest(**carry)` and change no signature (A P-4).
- **Callers of new names**: `write_change_document` gets a third caller and keeps its signature. `PatchEditorPanel.mark_saved` gets its first Save project caller (baseline-notes §4). Binding needs no `change_service.py` edit, because `ChangeDocument` is a mutable `@dataclass(slots=True)` with `source_path` (`changes/model.py:196,258`). See A3-14 (g).

## Findings

Severity: HIGH / MAJOR / MINOR / LOW. **Route:** `ruling` = the orchestrator decides (a requirement or pre-ruling changes); `proto` = a prototype text edit with no new decision.

### A3-1 — MAJOR — the document's problem name differs between B and A/R3 · route: proto (B)

- **Where:** B `check_project_files` func ("The problem's name is `path.name` ("boost.json")") and examples (B lines 78-86); B `_active_document_missing` examples (B lines 94-97); B design risk R-10. Against R3 ("the document's `ProjectFileProblem.file` is that same text in `check_project_files` and in the reopen") and A `_handle_load_project` example (A line 125, "naming "patches/boost.json" (from check_project_files)").
- **Scenario:** P is saved by the app, so `files` holds a record for `patches/boost.json`. The file is then overwritten with `{`. On Load, `_disk_problem` (`manifest_writer.py:1028`, `name = path.name`) gives `changed on disk` naming `boost.json`. The reopen gives `not readable` naming `patches/boost.json`. `merge_load_problems` keeps both (2 file keys), so TC-B100-30's "exactly 1 `not readable`" is RED. The `missing` arm also fails A line 125 (`boost.json` ≠ `patches/boost.json`).
- **Fix:** In B, the document's record (and `_active_document_missing`) names the project-relative POSIX text. Two ways: `check_project_files` passes the name into `_disk_problem` for the key equal to `manifest.active_document`, or it names any record whose parent is not the project root by its relative text. Change B's examples to `"patches/boost.json"`. Add one example: a `{` file with a record → `changed on disk` + `not readable` merged to 1 `not readable` naming `patches/boost.json`. `recorded = {path.name …}` (`manifest_writer.py:1104`) needs no change, because only top-level files are checked for `not recorded`.

### A3-2 — MAJOR — a missing or unreadable recorded document can never be dropped (R7 against the next-step tokens) · route: ruling

- **Where:** R7 ("A record whose file is missing is carried as recorded … never silently dropped"); B design risk R-9; A `_reopen_active_document` func (on `not readable` it rebinds an empty service "so a later Save project cannot re-record the bad file"). Against `PROBLEM_NEXT_STEP` (`variant_execution_service.py:1514-1515`): `missing` → "restore the file, or Save project to drop it"; `not readable` → "replace the file, or Save project to drop it" (LLR-169.6: 7 kinds → 7 tokens).
- **Scenario:** P records `active_document "patches/boost.json"` and the file is deleted. Load shows 1 `missing` row that says "…or Save project to drop it", and the editor is empty. The user runs Save project into P. Under R7 the session has no document, so the target's value is carried. `project_file_records` writes no record for it, and `serialize_manifest` writes the key because the writer does not check existence. On the next Load the same `missing` row appears, and this repeats forever. The only exits are pasting a new document or hand-editing `project.json`. The `{` (`not readable`) case loops the same way, so A's rebind rationale is void under R7. For every other recorded file the token is true, because Save project recomputes `files` from disk.
- **Fix (recommended ruling):** Save project (open project and merge), the one writer that rebuilds `files` from disk, drops a carried `active_document` whose file `os.lstat` reports absent, and writes 1 status line naming it. It may do the same for one that fails to parse, but that needs a read, so the absent case is the minimum. The four in-project carry writers keep the value verbatim, because they do not own the key (LLR-168.3 / SEC6-2 unchanged). LLR-164.2's negative control (the session's `None` passed in a merge with no session document) is unaffected, because its fixture has the file on disk. Amend LLR-164.2's threshold from "carried unchanged" to "carried unchanged while its file exists". Then edit B R-9, A `_handle_save_dialog` step (5), and A `_reopen_active_document`'s rationale. **Alternative:** keep R7 and give the document its own next-step token. That still leaves no drop path, so it is not recommended.

### A3-3 — MAJOR — no single rule for "the session holds a document, but nothing was placed" · route: ruling

- **Where:** HLR-170 / LLR-170.2 ("a write that fails … no `active_document` recorded"), R2 ("records no `active_document`" when the landing fails the form), R7 ("carry … when the session has no document"), LLR-164.2 threshold ("names the session's placed document when it holds one"). A covers only a fresh P (A line 53). The gather's refusals of a kind-(c) document (`GATHER-SOURCE-MISSING` at `project_gather_service.py:508-514`; `GATHER-CONTAINMENT`) fall in the same gap.
- **Scenario:** Save project merges into `ab`, whose `project.json` holds `active_document "patches/boost.json"`. The session holds a pasted document with 1 entry, and the document write is forced to fail. Read literally, HLR-170 gives no key, so `ab` loses its recorded document. That breaks LLR-164.2's "keeps the target's other keys" and the carry rule. R7 does not apply either, because the session "has a document". The open-project case has the same problem. The three texts give two different `project.json` outcomes, and a TC-B100-05 / TC-B100-29 author can write either one.
- **Fix (recommended ruling):** For the carry, "nothing placed" (failed write, gather refusal, R2 form failure) counts as "no session document". The target's value is carried for a merge or open-project save (subject to A3-2), and no key is written for a new target. HLR-170's "record no `active_document`" then reads "records none of its own". Add A examples: a merge into `ab` with a forced write failure → `active_document "patches/boost.json"`, 1 status line holding "not saved" and "changes.json", panel flag `True`.

### A3-4 — MAJOR — rule (b), in-place replace of any in-home file-backed document, goes beyond LLR-170.2 and conflicts with LLR-167.8's file-backed arm · route: ruling (requirement text)

- **Where:** A `_plan_project_save` func, rule (b), and A design risk R-5. R9 adopts the in-place replace mechanics but does not settle the scope. LLR-170.2's statement covers a document with no `source_path`, plus the Q1 sentence (a document "bound" after the first write). LLR-167.8's threshold reads "a file-backed document with 1 entry added after its load → Save project → True".
- **Scenario:** After 8a, the common path is: Load P (the reopen binds `P/patches/boost.json`) → add 1 entry → Save project into P. Rule (b) rewrites `boost.json` in place and the panel flag goes False. A TC author who builds LLR-167.8's file-backed arm from the requirement text, with this natural fixture, expects True and gets False. A dodges this only by choosing a common-library file (A line 58). The other reading, rewriting only documents "bound by Save project" (Q1 literally), is worse. The reopened document would go through gather case (b): it is named, not written, and the edits are lost on the next Load. A second effect: with no edit, a hand-formatted in-home document is rewritten in canonical form (the plan shows `replace`).
- **Fix (recommended ruling):** Keep rule (b). It is stateless and needs no "bound" marker that 4+ paths would have to clear. Amend the requirements to match:
  - LLR-170.2 and HLR-170: "a document whose file is in the target's home for its kind is rewritten in place (`replace` / `keep`); the gather places only documents from outside".
  - LLR-167.8's file-backed arm: "a file-backed document from outside the target project".
  - Specify the merge case that A leaves open (R9 says the target's document is never rewritten). In a merge, a session document whose source is in the target's home is treated as kind (a) and written under M-1 (`boost_1.json`), then recorded. Add 1 example to A and 1 to B (B line 136 covers only a pasted document).

### A3-5 — MAJOR — the rollback leaves the home folder that the app's document write created · route: proto (A)

- **Where:** A `_write_editor_document` (outputs: `placed`, `previous`, `failure`; no "created home"), A `_handle_save_dialog` step (3). Inc 7 / LED .53 rule: the rollback removes "the folders THIS save created" (`app.py:8924-8932`). Only the gather's `created_homes` and the project folder enter `created_dirs` (`app.py:9550-9551`).
- **Scenario:** Save project into a fresh `P` with a pasted 1-entry document, and the manifest write is forced to fail. The document write runs before the gather and creates `P/patches/` on demand (the copy helper creates the destination subdir, `changes/io.py` `write_change_document` docstring). When the gather runs later, the home already exists, so it reports none. The rollback unlinks `changes.json`. `P.rmdir()` then fails because `patches/` is still there, so an empty `P/patches/` is left in the work area. TC-B100-29's "0 new files under `patches/`" still passes, so no example catches it. The same happens with an existing project that has no `checks/`.
- **Fix:** `_write_editor_document` records whether the home existed before the write (`os.lstat`) and returns the created home. The handler appends it to `created_dirs`. Add an A example: the rollback arm → `P` absent (fresh target), or `P/patches/` absent (existing target with no home).

### A3-6 — MINOR — the plan's document row follows "is it recorded", not "does a file land" · route: proto (A)

- **Where:** A `_plan_project_save` (0 entries → no row, A line 36; a landing that fails the form → no row, A R-6). A `_handle_save_dialog` step (4) passes the document to the gather "only when the document has at least 1 entry". Against R8 (a file-backed document is gathered as today, at any entry count) and R2 (placed but not recorded).
- **Scenario:** A file-backed `boost.json` from the common folder has 0 entries. With R8, the gather writes `P/patches/boost.json`, but the plan has 0 document rows. The painted plan then differs from the written tree, against LLR-167.6 ("a file-backed document → 1 row … 0 differences"). Step (4) as written also contradicts R8.
- **Fix:** A document row exists exactly when a file lands: kind (a)/(b) with ≥1 entry, and kind (c) always. Recording `active_document` is a separate decision (≥1 entry, form passes). Pass the source to the gather as today. Update A lines 28, 36 and step (4).

### A3-7 — MINOR — the merge example's `gathered` disagrees between A and B · route: proto (A)

- **Where:** A `_handle_save_dialog` example (A line 61: "gathered holds "patches/boost.json" and "patches/changes.json""). B `gather_project_artifacts` case (b) (B line 106: an app-written in-home document gets "no "patches" row"). LLR-164.2: `gathered` = the target's entries plus the rows this save's gather adds.
- **Scenario:** Merge into `ab` with a pasted document. Following B, the gather adds no row, so A line 61's assertion fails. A R-1 already flagged this seam.
- **Fix:** Change A line 61 to "gathered holds "patches/boost.json" only (0 rows added); active_document "patches/changes.json"". `gathered` is read only by the carry (`app.py:10732`), so nothing else depends on the row.

### A3-8 — MINOR — R7 (open-project carry) is not carried through A · route: proto (A)

- **Where:** A `_save_manifest_keys` func ("OR a merge carries …"), `_plan_project_save` input `carried_active_document` ("in a merge"), `_handle_save_dialog` steps (1) and (5) ("when the target kind is "merge""), `_reopen_active_document` rationale, A R-12.
- **Scenario:** P is open and records `active_document`. The session has 0 entries, and Save project goes into P. The keys flag is False, so `plan.manifest_keys` lacks `active_document`, but under R7 the write records it. TC-B100-59's "`manifest_keys` holding `active_document` exactly when the write records it" is then RED.
- **Fix:** Change "merge" to "merge or open project" in those four places. Add an open-project example to `_save_manifest_keys` and `_handle_save_dialog`. Drop R-12, which R7 supersedes. Fold in the outcome of A3-2.

### A3-9 — MINOR — three predicates for "the document is already in its home" · route: proto (A, B)

- **Where:** A rule (b) "`source_path` inside the target's home" (unresolved, includes sub-folders). B `plan_project_save` "the source resolves to `target.resolve() / home / name`". B gather case (b) "`resolved.parent == resolved_project / home` and a regular non-reparse file per `os.lstat`".
- **Scenario:** A document loaded from `P/patches/sub/x.json` is kind (b) for A, so the app writes `P/patches/x.json` and clears the flag. It is not bound, so the editor still points to `sub/x.json` while `project.json` records `patches/x.json`. For B's planner it is not in-home. A symlink `P/patches/a.json` → outside is in-home for A by its unresolved path, but outside for B, which copies it to `a_1.json`. The three disagree on which code places the file.
- **Fix:** Use one predicate, owned by `project_gather_service` and used by the planner and the gather. The app executes the planner's row instead of deciding the kind again.

### A3-10 — MINOR — the new `_parsed_paste_text` attribute is missing from the session-snapshot census · route: proto (A)

- **Where:** A entity `[Data: S19TuiApp._parsed_paste_text]` (R10). `_SESSION_SNAPSHOT_NAMES` (`app.py:1692-1705`): the test census derives every `self.<name> =` at run time and fails when the tuple and the source drift.
- **Fix:** List it in `_SESSION_SNAPSHOT_NAMES` with its classification (the reset seam clears it) and add a TC-B100-09-family example. Without this, E4 meets a guard failure in E6.

### A3-11 — MINOR — R12 adds `_missing_recorded` with no requirement arm and no example · route: ruling (trace) + proto (C)

- **Where:** R12 ("`_missing_recorded` restricted to primary data suffixes joins 8a"). C R6 describes the defect, but no graph node, example or LLR names it.
- **Scenario:** `active_variant "boost"` is missing and `files` holds `patches/boost.json`. The Load summary names `boost.json`. A code change with no requirement breaks the code→R trace rule.
- **Fix:** The ruling names the owning LLR (LLR-169.6, the load summary) and its arm. Add a C node and example: the case above → the summary names no `boost.json` (it names the variant as missing). Negative control: drop the suffix filter → `boost.json` is named → RED.

### A3-12 — LOW — the landing text is built from a resolved path · route: proto (B)

- **Where:** R3 / B P-1: the gather computes the text "from the resolved project folder".
- **Scenario:** On Windows `resolve()` returns the on-disk case. A hand-made `P/Patches/` therefore gives `"Patches/x.json"`, which fails R1's exact home match. The app wrote the file, but records nothing (R2 status line).
- **Fix:** Build the text as `f"{home}/{landing.name}"` from the home constant and the placement's file name.

### A3-13 — LOW — R2's promise rests on a check narrower than the writer's · route: none (record)

- **Where:** R2 (the app checks `is_active_document_form` before recording). `serialize_manifest` also walks (`_reject_unsafe_entry`; a link as the final file is refused, B lines 28-29).
- **Scenario:** A link appears at the landing between the placement and the manifest write. The serialize refuses and the save rolls back, against R2's "the manifest is never refused because of the document". This is reachable only by a race, because placements, the gather and the reader already refuse links.
- **Fix:** Record it as the Inc 7 TOCTOU class (as R11 does). No design change.

### A3-14 — LOW — prototype text edits, no decision · route: proto

- (a) B entity `[Data: GatherOutcome.active_document]` says `Optional[Path]` (absolute), and B examples lines 106-118 say "ends … (absolute)". R3 makes it `Optional[str]`. Change them to project-relative text.
- (b) B entity `PlannedFile.home: str = ""` against R5 `Optional[str]`. Pick one; `""` is fine if R5 is restated.
- (c) R4 (writer refuses a sub-folder `files` key unless it equals `active_document`) has no B example. Add: `files` key `"patches/other.json"`, `active_document "patches/boost.json"` → `(None, 1 finding)`. Negative control: drop the check → serialized → RED.
- (d) A rollback example (A line 54) does not assert the flag. Add "panel flag `True`" (LLR-167.8's "rolled-back" arm).
- (e) A `_reopen_active_document` calls "0 entries with a path" a file-level fault. Say it means "the reader returned no document". Add an example: a valid v2 file with `"entries": []` → problem `None`, 0 entries. The file parses, so it is not `not readable`.
- (f) HLR-170's invalid arm ("outside `patches/`/`checks/` or not `.json` → the load continues and lists the problem") has no app-level example. Add to A `_handle_load_project`: `active_document "firmware.s19"` → 1 `manifest damaged` row (the reader's skipped entry), the image opens, 0 editor entries.
- (g) A `_handle_save_dialog` step (6) does not state how it binds. `ChangeService` has no setter and `ChangeService.save` never binds (`change_service.py:1772-1785`). State that the app sets `self._change_service.document.source_path` directly (mutable slots dataclass), so `change_service.py` stays outside the 4-file budget.

## Inc 7 rules (`increment-007.md` §6) — reopened or not

| Rule | Status in the 8a design |
|---|---|
| SEC6-2 refuse-rewrite | kept. A refused `active_document` is a skipped entry, so the rewrite is refused (C R4). |
| SEC6-5 / F2 row bound | kept. The document is parsed first, so its row is never folded (C). |
| SEC7-1 / R2-2 ceiling, 32-component cap, CI-6-1 text length | kept. The form is decided on the text; at most 2 folder checks (B R-11, C R4). |
| SEC7-R2-2 one walk per serialize | kept (B `serialize_manifest`). |
| SEC7-3 keep `.previous` | kept. The result changes only because the key is now known (C `manifest_keep_reason`). |
| Final-file link refused | kept at the writer, in `project_file_records` and in the gather (B). |
| LED .53 exact-removal rollback | **reopened by A3-5** (an app-created home is not listed). The never-delete-a-reused-file half is kept (B R-7, A `_write_editor_document`). |
| TC-B100-21 byte identity | kept (key last, only when set). |
| OBS-7-1 `_relation_line` | no effect (C R7). |
| R2-3, SEC7-4 (b) | still backlog; 8a does not touch them. |

## Observations (not findings)

- **Open-project Save project drops `gathered` rows.** For a document already inside P, `gathered` takes only this save's gather rows (`app.py:9615`), so the row from an earlier gather is lost on a Load → Save P round trip. This behaviour is older than 8a. 8a makes the path common, because the reopened document is always inside P. `gathered` is read only by the carry (`app.py:10732`), so there is no functional effect. Backlog candidate.
- **Undo after a reopen** goes to the backlog (R12).
- **TOCTOU on the reopen** (R11) is accepted.

## Architect evidence checklist

- ✓ Constraints stated: 4-source budget (E1 §3), Inc 7 rules (table above), R1–R12 as fixed inputs.
- ✓ Alternatives where a real decision exists: A3-2 (drop at Save project vs a new token), A3-4 (stateless rule (b) vs a "bound" marker). Elsewhere `n/a`: the decision was already made by R1–R12 or by existing seams.
- ✓ Recommendation with rationale: each finding's Fix.
- ✓ Risks: the findings. Cost/latency `n/a`: no new I/O beyond C's 2 `lstat` calls and B's 1 `lstat` + 1 hash per save.
- ✓ Diagram: `n/a`. The flows are linear and are in A's entity sequences.
- ✓ What would change the verdict: rulings on A3-2/3/4 plus prototype edits for A3-1/5 → re-read → expected `PASS-WITH-NOTES`.
- Evidence state of every source claim: `executed` (read at `dc3b314`); every scenario: `planned` (reasoned, not run).

## Round 2

Reviewer: architect (a fresh instance). Round 1 above is kept as written. This review is read-only toward the design; this section is its only write.

**Inputs read in full:**
- `E3-rulings.md` (R1–R9)
- `codewire/interfaces-8a.md`
- `codewire/proto-8a-app.md` (A)
- `codewire/proto-8a-writer-gather.md` (B, the rebuilt file)
- `codewire/proto-8a-reader.md` (C)
- `codewire/baseline-8a.md` (the B-owned nodes)
- `01-requirements.md` (HLR-170, LLR-164.2, LLR-167.6, LLR-167.8, LLR-169.5, LLR-170.1–170.3)
- `01-requirements-ledger.md` LED .73

Source claims were checked at `dc3b314` and are cited `file:line`. Every scenario below is `planned` (reasoned, not run).

### Verdict

**FAIL.** Two MAJOR findings are open:
- **A3R2-1 (new):** the planner and the gather disagree on a file-backed document that is inside the project but not in its home, or whose source is gone. The new digest of that source also refuses the whole save.
- **A3R2-2:** R8 is not reflected, and A states the opposite of R8.

Both are text edits to the graph and the requirements. Neither needs a decision beyond R8 itself.

The R1 rewrite is clean:
- `replace` is gone from the three graphs and from the requirements.
- LLR-155.3 holds with no exception.
- The rollback has no restore channel left.

Expected verdict after the A3R2-1 and A3R2-2 edits: **PASS-WITH-NOTES**.

### (1) Round-1 findings

| Id | Status | Evidence now in the graph |
|---|---|---|
| A3-1 | closed | B `check_project_files` func ("`_disk_problem` takes the name for the key equal to `manifest.active_document`") and examples B 83-93 (with the `{` file merged to 1 `not readable`, and its negative control). A `_handle_load_project` examples A 149-150. B R-10. |
| A3-2 | **partly open** | The `missing` half is closed: A `_handle_save_dialog` step (1) drops the value on `FileNotFoundError` with 1 status line (examples A 76-77, 80), and LLR-164.2 has the threshold and the mutant. The `not readable` half was decided by R8 but is not reflected: A `_reopen_active_document` func and A R-16 still say the record is NOT dropped (see A3R2-2). |
| A3-3 | closed in the design; **residual in the text** | A steps (2) and (5), and example A 62 (a merge with a forced write failure carries `patches/boost.json`; flag True). LLR-164.2 has the R3 sentence and mutant. The HLR-170 and LLR-170.2 statements still say "record no `active_document`" with no qualifier (see A3R2-3). |
| A3-4 | closed (withdrawn by R1) | A R-5. A `_plan_project_save` example A 42 (Load P → `keep`). A `_handle_save_dialog` example A 71 (natural path: flag True, bytes unchanged). B `plan_project_save` example B 159 (a merge whose session document is in `ab`'s home → `keep`, 0 bytes changed). LLR-167.8 threshold (5 arms). |
| A3-5 | closed | A `_write_editor_document` outputs `created_home`; examples A 107-109; A step (3); rollback examples A 63-64. A fresh project folder is already removed through `created_project_dir` (`app.py:8925-8926`), so listing it again does no harm (`set(...)`). One LOW residual: see A3R2-8. |
| A3-6 | closed as written | A `_plan_project_save` func ("exactly when a file lands or is recorded"); examples A 40 and A 59. This rule now exposes A3R2-1: some rows are planned although no file lands and nothing is recorded. |
| A3-7 | closed | Example A 74 ("gathered holds "patches/boost.json" only (0 rows added by the gather)"). |
| A3-8 | closed, with a side effect | A `_save_manifest_keys` func and example A 25; A steps (1) and (5) ("merge or the open project"); example A 75; R-12 resolved. Side effect: step (1) now also carries `gathered` in an open-project save (see A3R2-4). |
| A3-9 | **open** | One shared test exists: B `document_in_home` (B 106-118), used by `plan_project_save` and by gather case (b). But the planner has no case (c). Example B 160 plans `P/patches/sub/x.json` as a copy into `patches/`. Example B 135 says the gather writes 0 bytes for the same source, names `None` and adds 1 issue. See A3R2-1. |
| A3-10 | closed | A entity `[Data: S19TuiApp._parsed_paste_text]` (A 195) and the census example A 97. |
| A3-11 | closed | C node `_missing_recorded` (C 210-219) with its negative control. LLR-169.5 has the threshold arm (E3 R7). |
| A3-12 | closed | B `gather_project_artifacts` func: the landing text is `f"{home}/{landing.name}"`, built from the home constant. Same in entity `GatherOutcome.active_document`. Example B 134 is wrong on Windows (see A3R2-7, LOW). |
| A3-13 | closed (recorded) | A R-15. |
| A3-14 (a) | closed | B entity `GatherOutcome.active_document` is `Optional[str]`; examples B 127-133 use relative text. Stale copies remain in `interfaces-8a.md` line 22 and in C P3 (see A3R2-9). |
| A3-14 (b) | closed | B entity `PlannedFile.home` is `Optional[str]`, default None. |
| A3-14 (c) | closed | B `serialize_manifest` example B 32 with its negative control. |
| A3-14 (d) | closed | Examples A 61-64 assert the flag. |
| A3-14 (e) | closed | A `_reopen_active_document` func ("a valid v2 file with `"entries": []` is NOT a fault") and example A 170. |
| A3-14 (f) | closed | A `_handle_load_project` example A 152. |
| A3-14 (g) | closed | A step (6) sets `self._change_service.document.source_path` directly. |

### (2) R1–R9 consistency across A, B, C, `interfaces-8a.md` and the requirements

| Ruling | A | B | C | interfaces | requirements | Result |
|---|---|---|---|---|---|---|
| R1: no in-place rewrite; actions `new` / `keep` | ✓ R-5, R-7, R-8 withdrawn; lines 37, 42, 44, 66-67, 71 | ✓ plan func; examples 152-154, 159; entities; R-6 | ✓ header | ✓ pre-ruling 5; pre-ruling 9 superseded; line 50. Lines 22-23 still list `Optional[Path]` and `replace` (A3R2-9) | ✓ LLR-170.2, LLR-167.6, LLR-167.8. HLR-170's boundary catalog still says "reused, M-1" (A3R2-9) | consistent |
| R2: drop an absent carried value | ✓ step (1); lines 26, 76-77, 80 | ✓ serialize func, R-9, R-11 | n/a | ✓ pre-ruling 7 note; line 51 | ✓ LLR-164.2 | consistent |
| R3: not placed counts as no session document | ✓ steps (2) and (5); line 62 | ✓ entity `GatherOutcome.active_document` ("not placed" → None) | n/a | ✓ line 52 | ✓ LLR-164.2. HLR-170 and LLR-170.2 have no qualifier (A3R2-3) | text gap |
| R4: reopen caps | ✓ `_reopen_active_document` (pre-parse count, probe P1); lines 153, 172-177 | n/a | n/a | ✓ line 53 | ✓ LLR-170.3 | consistent |
| R5: refused target value → `.previous-<UTC>` | ✓ step (1); lines 78, 81 | ✓ R-3 | ✓ `manifest_keep_reason` (C 178-188), R4 | ✓ line 54 | ✓ LLR-164.2 | consistent |
| R6: user-terms text; C0/C1 refused | ✓ lines 82-83, 112-113, 168 | ✓ line 34 | ✓ lines 80, 94-95, 122 | ✓ pre-ruling 1 note; line 55 | n/a (design examples, LED .73) | consistent |
| R7: `_missing_recorded` | n/a | n/a | ✓ | ✓ line 56 | ✓ LLR-169.5 | consistent |
| R8: drop a carried value whose file is present but not readable | **✗ A says the opposite** (`_reopen_active_document` func, R-16) | ✗ serialize func, R-9 and R-11 name only the absent case | n/a | ✗ not listed | ✗ LLR-164.2 names only "absent" | A3R2-2 |
| R9: the ≥1-entry rule applies to a pasted document only | ✓ `_plan_project_save` func; lines 40, 59; R-10 | ✓ last sentence of the gather func | n/a | ✓ pre-ruling 8. R9 itself is not listed | ✗ HLR-170 statement and boundary catalog | A3R2-3 |

These shared values were checked in every file:
- the problem text `patches/boost.json` (A 76-77, 149-150, 163, 168; B 83-104; C 104, 118);
- the landing names `patches/changes.json`, `changes_1.json` and `checks/changes.json`;
- the codes `MANIFEST-PATH-ESCAPE`, `MANIFEST-BAD-STRUCTURE` and `MANIFEST-WRITE-ESCAPE`;
- the caps, 1 048 576 bytes and 1 000 entries;
- the counts in the three headers against their node lists (A: 9 nodes; B: 9 nodes, 4 entities, 3 findings; C: 10 nodes).

No other disagreement was found.

### (3) New findings

#### A3R2-1 — MAJOR — the plan and the gather disagree for some file-backed documents, and the new digest refuses the whole save · route: proto (A, B) + 1 threshold arm

**Where:**
- B `plan_project_save` has two branches only. If `document_in_home(…)` is True → `keep`. Otherwise → `predict_placement(…)`: reused → `keep`, else `new`.
- B `gather_project_artifacts` has three cases: (a) outside the project → copy; (b) in its home → name it; (c) inside the project anywhere else → no copy, `None`, 1 finding.
- Example B 160 says `P/patches/sub/x.json` is "copied under its name into `patches/`". Example B 135 says the gather writes 0 bytes for the same source, returns `None` and adds 1 issue.
- A `_plan_project_save` (b) computes `_file_digest` of the source for every file-backed document.

**Scenario 1 — the plan differs from the written tree.**
1. A change document is loaded from `P/notes/x.json`, `P/x.json` or `P/patches/sub/x.json`.
2. Save project into P.
3. The plan paints a document row `patches/x.json` `new`, and `manifest_keys` holds `active_document`.
4. The gather writes nothing and names `None`.

LLR-167.6 asks for 0 differences. A step (2) checks the gather's landing against the row, but no rule says what happens to a row with no landing: abort, or a silent difference.

**Scenario 2 — the save is refused (a regression).**
1. A file-backed document is loaded from the common library, and that file is then renamed or deleted. (Or: Load P, then `P/patches/boost.json` is deleted while the editor still holds it.)
2. `_plan_project_save` now digests the source. `_file_digest` raises `OSError`.
3. The caller refuses the whole save before any folder exists: "Project NOT saved: … could not be read. Nothing written." (`app.py:9283-9300`; docstring `app.py:9891-9893`).

At `dc3b314` the plan does not cover the document. The gather only logs `GATHER-SOURCE-MISSING` (`project_gather_service.py:508-514`), and the save completes. The new behaviour also contradicts R3 and HLR-170's error arm ("Save project shall complete without it").

**Fix:**
1. Put one classifier in `project_gather_service`, for example `classify_active_document(project_dir, source, home) -> "in_home" | "outside" | "inside_elsewhere" | "missing"` (it can extend `document_in_home`). Call it from `plan_project_save` and from the gather.
2. Plan by class:
   - `in_home` → `keep`.
   - `outside` → the predicted `new` or `keep`.
   - `inside_elsewhere` and `missing` → 0 document rows. The gather adds its one finding, the document counts as "not placed" (R3), the carried value follows R2/R8, and 1 status line is painted.
3. In A `_plan_project_save`, digest each file-backed document's source on its own. An `OSError` on that source gives 0 document rows (the same "not placed" path) and never refuses the save. The image, MAC and A2L sources keep today's refusal.
4. Replace example B 160 with: `P/patches/sub/x.json` → 0 document rows. This matches B 135.
5. Add these examples to A:
   - a document from `P/notes/x.json` → 0 document rows, `manifest_keys` without `active_document` (no carried value) or with it (a carried value), 1 status line, the plan equals the tree;
   - the source deleted after the load → the save completes, 0 document rows, 1 status line, the R3 carry.
6. Add two negative controls:
   - the planner without the `inside_elsewhere` class → 1 row with no file → RED;
   - the digest `OSError` propagated → "Project NOT saved" → RED.
7. In LLR-167.6's Inc 8a arm, change "a file-backed document → 1 row with its landing name" to "a file-backed document that is placed or recorded → 1 row; one the gather does not place (inside the project but outside its home, or its source gone) → 0 rows".

#### A3R2-2 — MAJOR — R8 is not reflected, and A states the opposite · route: proto (A, B) + requirement text (LLR-164.2) + ledger

**Where:**
- A `_reopen_active_document` func: "Under pre-ruling 7 and R2 a carried record whose file is present but unreadable is not dropped by Save project (only an absent one is), so its row repeats on each Load until the file is replaced (R-16)". A R-16 says the same.
- A `_handle_save_dialog` step (1) tests only `FileNotFoundError`.
- A `_save_manifest_keys` sets the flag for a carried value "whose file exists on disk".
- LLR-164.2 says "whose file is absent from disk".

**Scenario:**
1. `P/patches/boost.json` holds `{`.
2. Load P lists 1 `not readable` row. Its next-step token says "Save project to drop it". The session holds no document.
3. Save P carries the value, because the file exists.
4. The next Load lists the same row.

This is round 1's A3-2 loop. It is still open for `not readable` and for "too large to reopen".

**Text that must change:**
1. A `_handle_save_dialog`:
   - Step (1): after "when the carried value's file is absent …", add: "or present but not readable — the same test the reopen applies (the two `os.lstat` guards on the home and the file, the 1 MiB / 1 000-entry caps, then a parse that returns no document), run on the absolute path `project_dir.absolute() / text` without touching the session's `ChangeService` — drop the value from this save and keep one status line naming it (E3 R8)".
   - Step (5): change "(an existing file, R2)" to "(an existing, readable file, R2/R8)".
2. A `_reopen_active_document`:
   - Delete the sentence "Under pre-ruling 7 and R2 … (R-16)".
   - State that the pre-parse guards, the caps and the parse are one helper, shared with Save project's drop test. Load's "not readable" and Save project's "dropped" then use the same predicate. Two copies of the helper could drift: a file could be listed `not readable` at Load and still be carried at Save.
   - The helper takes no `a2l_context`, because the decision does not depend on the A2L.
3. A R-16: mark it "RESOLVED by E3 R8".
4. A `_save_manifest_keys`:
   - Func: change "whose file exists on disk" to "whose file exists and is readable (R2, R8)".
   - Add an example: the open project with `{` in `patches/boost.json` and 0 session entries → flag `False`, keys without `active_document`.
5. A `_plan_project_save` func: change "already dropped by the handler when its file is absent (R2)" to "… absent or not readable (R2, R8)".
6. A `_handle_save_dialog`, examples to add:
   - P open, `P/patches/boost.json` holds `{`, 0 session entries, Save P → project.json has no `active_document`, 1 status line naming "patches/boost.json", and the next Load lists 0 problems for it.
   - The same with a file over the cap (1 001 entries) → dropped, 1 status line; the file stays on disk, unrecorded.
   - The merge arm, into `ab`.
   - Negative control: a mutation carrying a not-readable value → the next Load lists the same `not readable` row → RED.
7. B `serialize_manifest` func, R-9 and R-11: change "Save project drops it … when its file is absent" to "… absent or not readable (E3 R2, R8)".
8. `interfaces-8a.md`: add R8 and R9 lines under "E3 round-1 rulings applied", and extend pre-ruling 7's note.
9. LLR-164.2:
   - Threshold: change "carried unchanged, while its file exists on disk" to "… while its file exists on disk and is readable (LLR-170.3's test)".
   - Threshold: change "drops a carried `active_document` whose file is absent from disk" to "… absent from disk or present but not readable (a link, over the reopen caps, or not parsing as a change or check document), … the 'Save project to drop it' recovery of the `missing` and `not readable` rows".
   - Negative control: add "a mutation carrying a not-readable `active_document` → the next Load lists the same `not readable` row → RED (R8)".
10. Ledger: add a new LED entry (.74) for R8 and R9 with the before → after text. LED .73 lists only R1–R7.

**Note (not a finding):** R8 also drops the record of a valid document that is over the reopen caps. This happens on any Save project, not only on one the engineer makes to drop the record. The file stays on disk and the status line names it, as the ruling decides. The over-cap example in item 6 pins this, so E6 does not meet it as a surprise.

#### A3R2-3 — MINOR — R3 and R9 are not in HLR-170 and LLR-170.2 · route: requirement text

**Where:**
- HLR-170 statement: "When Save project runs while the Patch Editor holds a document with at least one entry, the system shall place that document …" and "… record no `active_document`".
- HLR-170 boundary catalog: "empty: a document with 0 entries (not recorded)" and "boundary: a file-backed document already in `P/patches/` (reused, M-1)".
- LLR-170.2 statement: "… no `active_document` recorded …". LLR-170.2 threshold: "a forced write failure → … no `active_document`".
- Example A 59 (a 0-entry file-backed document is copied and recorded) cites "pre-ruling 8". No requirement arm backs it.

**Scenario:** a TC-B100-29 author builds the failed-write arm as a merge into `ab`. HLR-170 and LLR-170.2 give "no `active_document`". LLR-164.2 (R3) gives "patches/boost.json carried". Under the trace rule, the 0-entry file-backed path also has no requirement.

**Fix:**
- HLR-170 statement: "… holds a document — a pasted document with at least one entry, or a file-backed document whatever its entry count (E3 R9) — …". Change "record no `active_document`" to "record no `active_document` of its own (a merge or an open-project save carries the target's value, LLR-164.2)".
- HLR-170 boundary catalog: "empty: a pasted document with 0 entries (not recorded)" and "boundary: a file-backed document already in `P/patches/` (recorded as on disk, `keep`, E3 R1)".
- LLR-170.2: add the same "of its own" qualifier to the statement and the threshold. Add the arm "a file-backed document with 0 entries → 1 file, recorded (E3 R9)".

#### A3R2-4 — MINOR — the open-project save now carries `gathered`, which no requirement asks for · route: proto (A)

**Where:**
- A `_handle_save_dialog` step (1): "When the target kind is "merge" or the open project (A3-8), take `carried_active_document` and the carried `gathered` from `_manifest_carry`".
- A R-17 says an open-project save keeps only this save's gather rows (`app.py:9615`, `gathered=gather_outcome.gathered`) and calls this a backlog candidate.
- LLR-164.2 sets `gathered` = the target's entries plus this save's rows only for a merge, case (b).

**Scenario:** two texts in A give two outcomes.
- An E4 implementer who follows step (1) changes the open-project `gathered` behaviour. No requirement arm or example covers that change, so the code→R trace has a gap.
- An implementer who follows R-17 leaves it unchanged, and step (1) is wrong.

**Fix (recommended):** step (1) carries `gathered` for a merge only, and carries `active_document` for a merge or the open project. R-17 stays in the backlog. The alternative is to close R-17 here, with an example and an LLR-164.2 arm.

#### A3R2-5 — MINOR — B omits the `PlannedFile.source` type change and drops one baseline "holds" example (likely lost in the truncation) · route: proto (B)

**Where:**
- Pre-ruling 5 and A P-1 make `PlannedFile.source` `Optional[Path]` (`None` for a pasted document). Today it is `source: Path` (`project_gather_service.py:726`), and B's planner reads `source` for `document_in_home`. B's entities list `PlannedFile.home`, `SavePlanRow.role` and the action words, but not `PlannedFile.source`, and not the role value "document" for `PlannedFile.role` (docstring at `project_gather_service.py:717`).
- The module comment at `project_gather_service.py:690-692` says `replace` "is added with the merge rows (Inc 8a)". 8a no longer adds it.
- `verify_written_manifest` lost baseline's "holds" arm: TC-B100-23, one digest changed → `mismatch` with drift holding "files". That arm guards against the new key hiding a `files` drift.

**Fix:**
- Add entity `[Data: PlannedFile.source]` `Optional[Path]`: "None for a pasted document; the planner skips `document_in_home` when None".
- Add the role value "document" to `PlannedFile.role`.
- Note that the module comment changes to "`merge` is added at 8a; `replace` is not produced at 8a".
- Restore the TC-B100-23 "holds" example in `verify_written_manifest`.

Nothing else from baseline's B-owned nodes is missing. These are all present: the 7 nodes, TC-B100-21 byte identity, TC-B100-27, the TC-B100-22 "holds" example, the `test_tc700_…` gather "holds" example and the TC-B100-59 fresh-folder "holds" example.

#### A3R2-6 — LOW — a link source is predicted under its own name and copied under its target's name · route: proto (B)

**Where:** B `plan_project_save` (and A `_plan_project_save` (b)) predict with "name = the source's name". The gather schedules `resolved_active` (`project_gather_service.py:498-505`), and the placement names the landing `resolved_source.name` (`workspace.py:1199`). Example B 138 (`P/patches/a.json` → `a_1.json`) assumes the two names are the same.

**Scenario:** `P/patches/a.json` is a link to `outside/real.json`. The plan paints `patches/a_1.json` `new`. The gather writes `patches/real.json`. That is 1 difference against LLR-167.6.

**Fix:** the planner predicts with the resolved source's name; the A3R2-1 classifier can return it. Rewrite example 138 with a link target that has a different name.

#### A3R2-7 — LOW — example B 134 (`P/Patches/`) contradicts `document_in_home`'s own comparison on Windows · route: proto (B)

**Where:** `document_in_home` compares the parent with `os.path.normcase`, which lowercases on Windows, and on Windows `os.lstat(P/patches)` finds a folder named `Patches`. Example B 134 says `document_in_home` is False because "the home must match the lowercase constant exactly".

**Scenario:** on Windows the example is RED by construction. The outcome itself does no harm: the text is built from the constant ("patches/x.json"), and the reader's walk finds the file.

**Fix (pick one and state it in the func):**
- split the example by platform: Windows → True, recorded "patches/x.json"; POSIX → False; or
- compare the home component exactly (`source.parent.name == home`) and keep `normcase` for the project part only.

#### A3R2-8 — LOW — `created_home` on the failure path of `_write_editor_document` · route: proto (A)

**Where:**
- A `_write_editor_document` decides `created_home` before the write.
- The handler does not abort when the document write fails.
- Step (3) does not say whether `created_home` enters `created_dirs` when the write failed.
- The placement creates the destination folder before staging. The gather handles this case "on BOTH paths" (the R5-1 rule, `project_gather_service.py:548-556`).

**Scenario:**
1. Save project into a fresh P.
2. The document write fails after it created `P/patches/`.
3. The manifest write then fails.
4. If `created_home` is not listed, `P/patches/` stays and `P.rmdir()` fails.

This is A3-5 again, on the failure path.

**Fix:**
- Step (3): "`created_home` joins `created_dirs` whether or not the write succeeded".
- Add 1 example: a forced document-write failure, then a forced manifest failure, in a fresh target → `P` absent.
- A completed save after a failed document write can leave an empty home. Record this; no change is needed.

#### A3R2-9 — LOW — stale text after R1 and R3 · route: proto and requirement text

- `interfaces-8a.md`:
  - line 22 says `GatherOutcome.active_document: Optional[Path]`;
  - line 23 lists the actions `new` / `replace` / `keep` (LED .72 Q3);
  - line 57 overrides both, but the two bullets still read as the interface. Strike them, or mark them superseded where they stand.
- C P3 rationale: "`GatherOutcome.active_document` is an absolute `Path` (group B)" is no longer true. Totality is still right; reword the reason.
- HLR-170 boundary catalog: "reused, M-1" (covered in A3R2-3).
- `01-requirements.md` line 38 (the Save plan glossary) still lists `replace` as an action word. Keep it only if Inc 8b produces `replace`, and say so.

### (4) R8 and R9

- **R8** is not reflected in any file (it was decided after the pass). A states the opposite in `_reopen_active_document` and R-16. The exact edits are the ten numbered items of A3R2-2.
- **R9** is reflected in the graph: A `_plan_project_save` func and lines 40 and 59, A R-10, the B gather func, and interfaces pre-ruling 8. It is not reflected in the requirements (HLR-170 statement and boundary catalog; a missing LLR-170.2 arm), and `interfaces-8a.md` does not list it. The exact edits are in A3R2-3 and A3R2-2 item 8.

### Seams, ordering, rollback, carry, one problem per file, Inc 7 rules — checked, no further finding

- **Save order:**
  1. the plan;
  2. one read of the target for R2 / R5 (and R8);
  3. the rows loop (the document write; a mismatch aborts, a failed write does not);
  4. the gather (case (b) names the app's landing with no `written` entry; `created_homes` leaves out the home the app made, because that home now exists, `project_gather_service.py:536`);
  5. the manifest write and verify;
  6. the commit block (bind, re-render, `mark_saved`).

  The bind happens only after `project.json` is on disk.
- **Rollback:** no restore list is needed (R1). `placed_files` holds only files this save created, never a reused one (R-7). Created homes are removed deepest first (`app.py:8924-8932`).
- **Carry:** `_manifest_carry` → `_rewrite_project_manifest(**carry)` → `_write_and_verify_manifest(active_document=…)` → `project_file_records`, `write_project_manifest` and `verify_written_manifest`, for all four carry writers. The carry writers keep the value as written, even when the file is absent or unreadable. Only Save project drops it. The merge and open-project paths read the carry once (`app.py:9272`).
- **One problem per file:**
  - `_disk_problem`, `_active_document_missing` and the reopen all use one text, "patches/boost.json".
  - The R4 caps give `not readable`, which outranks `changed on disk` (`variant_execution_service.py:1500-1508`).
  - After an R2 / R8 drop, the next Load lists 0 problems for the document, because sub-folder files are never `not recorded`.
- **Inc 7 rules:** the round-1 table still holds. LED .53 is no longer reopened: A3-5 is closed, and A3R2-8 is its failure-path corner. The R8 read is a new read in Save project. It must reuse S3-9's two `lstat` guards and the R4 caps (A3R2-2 item 2). The SEC7-1 / R2-2 costs then stay the same: at most 2 `lstat` calls and at most 1 MiB read.

### Architect evidence checklist (round 2)

- ✓ **Constraints:** R1–R9 are fixed inputs, together with the 4-source budget and the Inc 7 rules. No finding adds a source file: the classifier goes in `project_gather_service.py`, and the shared readability helper goes in `app.py`.
- ✓ **Alternatives where a decision remains:** A3R2-4 (merge only, or close R-17) and A3R2-7 (an example split by platform, or an exact home component). Elsewhere `n/a`, because the fix follows from a ruling.
- ✓ **Recommendation with rationale:** in each finding's Fix.
- ✓ **What would change the verdict:** the A3R2-1 and A3R2-2 edits, then a re-read → expected PASS-WITH-NOTES. A3R2-3 to A3R2-9 can land in the same pass.
- **Evidence state:** source claims are `executed` (read at `dc3b314`); scenarios are `planned`.

## Round 3

Verification only (2026-10-30). Inputs read: `E3-rulings.md` (R1–R14, R8 refined), `codewire/proto-8a-app.md` (A), `codewire/proto-8a-writer-gather.md` (B), `codewire/proto-8a-reader.md` (C), `codewire/interfaces-8a.md`, `01-requirements.md` (HLR-170, LLR-164.2, LLR-167.6, LLR-170.2, LLR-170.3, the §1.3 Save plan glossary, the §3 token table rows for `not readable`), `01-requirements-ledger.md` LED .74 with its addendum. Source claims were checked at `dc3b314` (`changes/io.py` `parse_change_document` and `_metadata_issues`, `app.py` :9244).

### Verdict

**PASS-WITH-NOTES.** A3R2-1 … A3R2-9 are closed. R8 refined and R10–R14 read the same in A, B, C, the interfaces and the requirements. The pass added no MAJOR or HIGH defect. Three MINOR and two LOW items are open; none blocks E4. They can land in the E4 brief or in one text pass.

### (1) Round-2 findings

| Id | State | Where it is closed (node · example) |
|---|---|---|
| A3R2-1 | closed | B `classify_active_document` (4 classes, "inside" on the unresolved text), called by B `plan_project_save`, B `gather_project_artifacts` and A `_plan_project_save` (b); the document digest is computed on its own under `try/except OSError` → 0 rows, never "Project NOT saved". Examples: A `P/notes/x.json` → 0 rows, keys without/with the carried value; A deleted source → class `missing`, plan computed; A and B negative controls (no `inside_elsewhere` → RED; digest `OSError` propagated → RED); B `P/patches/sub/x.json` → 0 rows (replaces old example 160); A `_handle_save_dialog` "source deleted after load, merge into `ab`" → R3 carry. LLR-167.6 arm and both mutants present. |
| A3R2-2 | closed | A `recorded_document_state` (the one classifier) used by `_reopen_active_document` and `_handle_save_dialog` step (1); `_save_manifest_keys` func and examples (`{` → dropped; 1 500 entries → kept); `_plan_project_save` func; R-16 marked resolved; B `serialize_manifest`, R-9, R-11; interfaces R8 line and pre-ruling 7 note; LLR-164.2 threshold, R8 / R8-refined / R10 mutants; LED .74. Examples: A `{` → dropped, next Load 0 problems; a link → dropped; merge arm; negative control "carrying an `unreadable` value → RED". Item 6's over-cap "dropped" example is superseded by R8 refined and replaced by the kept arms (1 500 entries; 20 000-entry merge under 1 s; mutant "dropping a `too_large` value → RED"). Item 2's "no `a2l_context`" is superseded by R10 as written in the interfaces (optional, Save passes `None`, outcome independent of it; see A3R3-3). |
| A3R2-3 | closed | HLR-170 statement ("a pasted document with at least one entry, or a file-backed document whatever its entry count"; "no `active_document` of its own"), threshold failed-write arm and boundary catalog; LLR-170.2 statement, threshold (0-entry file-backed → 1 file, recorded) and boundary catalog. |
| A3R2-4 | closed | A `_handle_save_dialog` step (1) carries `gathered` for a merge only; R-17 stays backlog; example "`P` open … gathered equals this save's gather rows; merge into `ab` … holds `patches/a.json`". |
| A3R2-5 | closed | B entities `PlannedFile.source` (`Optional[Path]`), `PlannedFile.role` ("document"), plan action words (module-comment note); `verify_written_manifest` TC-B100-23 "holds" example restored. |
| A3R2-6 | closed | B `classify_active_document` returns the placed name; a link source is class `missing` (S3R2-5), so the two names cannot differ. Example: B `plan_project_save` `P/patches/a.json` → link → 0 rows. |
| A3R2-7 | closed | B `document_in_home` compares the home component exactly (option 2, stated in the func); examples `P/Patches/x.json` → False on both platforms, gather → `inside_elsewhere`. |
| A3R2-8 | closed | A `_handle_save_dialog` step (3) ("`created_home` joins `created_dirs` whether or not the write succeeded"); `_write_editor_document` returns `created_home` on every outcome. Examples: `_write_editor_document` failure after the home was created → `created_home` "P/patches"; handler: failed document write then failed manifest write → `P` absent. |
| A3R2-9 | closed | interfaces lines 22–23 struck and marked superseded; C P3 reason reworded; HLR-170 boundary catalog; §1.3 glossary drops `replace` with the Inc 8a note. LED .74 addendum keeps HLR-175's `replace` (outside the document row). |

### (2) R8 refined and R10–R14 across the files

| Ruling | A | B | C | interfaces | requirements |
|---|---|---|---|---|---|
| R8 refined: drop on `missing` / `link` / `unreadable`, keep on `too_large` / `io_error` | ✓ `_handle_save_dialog` (1), `_save_manifest_keys`, `_plan_project_save`, `_manifest_carry`, `RecordedDocumentState`, R-12 | ✓ `serialize_manifest`, R-9, R-11 | n/a | ✓ R8 line, pre-ruling 7 note | ✓ LLR-164.2, LLR-170.3 ("the record stays … only Save project drops it"), token rows 361–362 |
| R10: one classifier, order lstat → size cap → one read → guarded decode + count → parse of the same bytes | ✓ `recorded_document_state`; the reopen installs its document, no `ChangeService.load` | ✓ `_active_document_missing` defers to it | ✓ R3 note | ✓ R10 line | ✓ LLR-170.3 statement, threshold, mutants |
| R11: one gather classifier | ✓ `_plan_project_save` (b), handler (2)/(4) | ✓ `classify_active_document`, planner, gather | ✓ R1 note | ✓ R11 line | ✓ LLR-167.6, LLR-164.2 |
| R12: bind = unresolved `project_dir / home / name` | ✓ handler (6), entity, R-19, example | ✓ gather case (b) | n/a | ✓ | n/a (design) |
| R13: `gathered` carried for a merge only | ✓ | n/a | n/a | ✓ | ✓ LLR-164.2 (b) only |
| R14: requirement text + LED .74 | — | — | — | ✓ | ✓ |

Node and entity counts in the A and B headers match their bodies (A: 10 nodes; B: 10 nodes, 6 entities).

### (3) Open items

#### A3R3-1 — MINOR — Save project paints the carried value's drop / `io_error` line even when the session document replaces the record · route: proto (A) + LLR-164.2 wording

**Where:** A `_handle_save_dialog` step (1) classifies the carried value "before the plan" and paints the line there: drop → "one status line naming it"; `io_error` → "could not be checked and stays recorded". The line does not depend on whether the session holds a document that is placed.

**Scenario:** `P` open, `P/patches/boost.json` locked by another program, 1 entry pasted, Save project into `P` → project.json records "patches/changes.json", and the status says the change document "stays recorded". That is false: the record was replaced. With `{` in `boost.json` the drop line names a value the save would have replaced anyway.

**Fix:** keep the classification in step (1) (the R3 carry needs it after a failed write). Paint its line in step (5) only when the carried value is the one this save would write. Add one example: the locked-file case above → active_document "patches/changes.json", `0` status lines naming "patches/boost.json". In LLR-164.2, "1 status line for `io_error`" becomes "… when the carried value is the one recorded".

#### A3R3-2 — MINOR — the `io_error` reason differs between the token table and LLR-170.3 / A, and is narrower than the class · route: requirement text + proto (A)

**Where:**
- §3 token row 362: `not readable` + `in use by another program` → `close the program holding it and Load again`.
- LLR-170.3 statement and threshold: "could not be read now".
- A `_reopen_active_document`: "it could not be read now". A `_handle_save_dialog`: "could not be checked".
- A `recorded_document_state`: `io_error` = any `OSError` other than `FileNotFoundError` on `lstat`, open or read (a permission denial, a network share gone, an I/O error), not only a sharing violation.

**Scenario:** a TC-B100-30 author asserts the token row's reason and the A example asserts "could not be read now": one of them is RED. A permission-denied file is painted "in use by another program", which is not true.

**Fix:** one reason in all three places, true for the whole class. For example: reason `could not be read now`, next step `close any program holding it or check its permissions, then Load again`. Note (no change asked): row 361's next step `open it from the Patch Editor` runs the Patch Editor's uncapped load. For the 20 000-entry document of R4 that is the 33 s parse. The advice is honest for the app's own 1 001–2 000-entry documents.

#### A3R3-3 — MINOR — "a file-level ERROR finding" cannot be told from an entry finding by severity · route: proto (A)

**Where:** A `recorded_document_state` step (5): "a document with a file-level ERROR finding (JSON parse, bad structure, v1 format, metadata) → `unreadable`". At `dc3b314`, `parse_change_document` puts file-level and entry-level findings in one `issues` list, and every read-path finding is `ERROR` (`changes/io.py` `_issue`, `parse_change_document` lines 565–628).

**Scenario:** an implementer tests "any ERROR in `document.issues`". Save project calls the classifier with `a2l_context=None`. An open project whose recorded document holds 1 symbol entry gives `CHG-SYMBOL-UNRESOLVED`, so the class is `unreadable`, and Save project drops the app's own valid record. The reopen also lists a document with 1 blocked entry as `not readable`. Examples A `recorded_document_state` "1 symbol entry … outcome ok both times" and A `_reopen_active_document` "1 blocked entry → problem None" would catch it, but the func does not say how to decide.

**Fix:** name the file-level code set in the func: `MF-JSON-PARSE`, `MF-BAD-STRUCTURE`, `CHG-V1-FORMAT`, `CHG-FORMAT`, `CHG-KIND-UNKNOWN`, `CHG-ENCODING-UNKNOWN`, `CHG-VALUE-MODE-UNKNOWN` (the only codes emitted before `_parse_entries`). Add one Save-level example: `P` open, its recorded document holds 1 symbol entry, 0 session entries, Save project into `P` → active_document kept, 0 status lines. Add one mutant: "any ERROR → `unreadable`" → that record dropped → RED.

#### A3R3-4 — LOW — A R-16 is stale after the LED .74 addendum · route: proto (A)

A R-16 still reads "Open point … the token table is outside this pass" and proposes the over-cap token. The addendum added rows 361–362. **Fix:** "RESOLVED by E3 R8 refined and the LED .74 addendum (token rows 361–362)", after A3R3-2 is settled.

#### A3R3-5 — LOW — a home that is a regular file gives `missing` in B and `unreadable` in A on Windows · route: record (or one sentence in A)

On Windows, `os.lstat("P/patches/boost.json")` raises `FileNotFoundError` when `P/patches` is a file. B `_active_document_missing` then reports `missing`. A `recorded_document_state` checks the home first and says `unreadable`. `merge_load_problems` keeps one problem (`missing`, by precedence), and Save project drops the value under either class. So the outcome is the same, but B's sentence "one file is never `missing` here and `not readable` there" is not exact. **Fix:** state the classifier's step (1) order (home first: `FileNotFoundError` → `missing`, link → `link`, not a directory → `unreadable`, then the file), and soften B's sentence. No example needed.

### Checked, no finding

- **Save order with the classifier:** step (1) is one read of the target manifest, then at most 2 `lstat` and at most 1 048 577 bytes. A never-loaded 20 000-entry merge target stops at the size cap: 0 bytes read, not parsed.
- **Plan and tree agree for every R11 class:** `outside` copies that the gather refuses (a junctioned home, the form guard) stay in R-9's recorded plan-versus-failure class, unchanged from round 2.
- **R12 spellings:** the Save target is `parent_resolved / cleaned` (`app.py` :9244), the bind uses the same `project_dir`, and the reopen uses `project_dir.absolute() / text`. If Load and Save spell the work area differently, the in-home test says `outside`. The gather then reuses the identical file (`keep`, "patches/boost.json"). This is benign, so no finding.
- **Check documents:** `parse_change_document` reads both kinds (one schema, `kind` in `DOCUMENT_KINDS`), so a `checks/` record is not `unreadable` by kind.

### Architect evidence checklist (round 3)

- ✓ Constraints: R1–R14 are fixed inputs; no item adds a source file.
- ✓ Alternatives: A3R3-1 (paint late, or classify only when no session row: paint late is chosen, because R3 needs the class after a failed write); A3R3-2 (wording only).
- ✓ What would change the verdict: a MAJOR would need a scenario where Save project drops a valid record, or Load fails. A3R3-3 is the closest; the existing examples catch it.
- Evidence state: source claims `executed` (read at `dc3b314`); scenarios `planned`.
