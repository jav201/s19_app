# Code-Wire prototype — Inc 8a group C, the manifest reader (`variant_execution_service.py`)

Step E2 of `../PLAN.md`, group C (E1-scope §3, G3). Base: worktree `b100-inc8a` at `dc3b314`. This file is the design only: no source file was changed (operator ruling: the prototype is the graph; new functions and fields are nodes marked "new" in `func:`, with no stub and no mark in the code).

Interface source: `interfaces-8a.md` (fixed). Where E1-scope §3 D2 says `ProjectManifest.active_document: Optional[Path]`, this file follows the interface (`Optional[str]`), the more recent and fixed text.

E3 round 1 (2026-10-30): the rulings R1-R7 of `../E3-rulings.md` and the listed prototype edits are applied in this file. Changes here: `is_active_document_form` refuses C0/C1 control characters and compares the `.json` suffix case-insensitively (pre-ruling 1, E3 R6); `manifest_keep_reason` fires for a refused `active_document` (E3 R5); `_missing_recorded` is a node with its requirement arm (E3 R7, LLR-169.5); the examples agree with the rulings (S3-12). One problem text `patches/boost.json`; `GatherOutcome.active_document: Optional[str]`; `PlannedFile.home: Optional[str]`; actions `new` / `keep`.

E3 round 2 (2026-10-30): no node of this file changes. The reader's rules stay as written; the texts that named other groups are aligned: P3's reason (A3R2-9), R1's second path (E3 R11: class `inside_elsewhere`) and R3 (the reopen now reads through the app's one classifier `recorded_document_state`, E3 R10, not `ChangeService.load`).

Example sources: `01-requirements.md` thresholds (LLR-170.1 / TC-B100-28, LLR-169.4 / TC-B100-24, LLR-169.2 A-15 arm / TC-B100-22, LLR-168.3 / AT-B100-20, LLR-169.5 / TC-B100-25) and the Inc 7 rulings in `03-increments/increment-007.md` §6 (SEC6-2, SEC6-5, SEC7-1, SEC7-R2-1, R2-2, CI-6-1). A line that rests on a choice made here, because no requirement fixes it, says `design choice, E3` in its source. Issue codes: `PE` = `MANIFEST-PATH-ESCAPE`, `BS` = `MANIFEST-BAD-STRUCTURE` (written out in full in the anchors).

The order of this file: summary, design risks, proposed interface changes, the outside readers, then the graph (`## Nodes`, `## Entities`, `## Edges`).

### Summary

- 10 nodes: 2 new (`is_active_document_form`, `_parse_manifest_active_document`), 5 changed (`read_project_manifest`, `_recorded_file`, `_parse_manifest_files`, `manifest_keep_reason`, `_missing_recorded`), 3 unchanged but with new 8a examples (`_parse_manifest_derived_from`, `manifest_rewrite_refusal`, `execute_project_variants`). 2 data entities (`KNOWN_MANIFEST_KEYS`, `ProjectManifest.active_document`) plus `ProjectManifest.files` and `_EntryWalk` as context.
- The reader decides `active_document` in the same three steps as a `files` key (`_recorded_file`, the Inc 7 pattern): the shared text rules (`_entry_text`, manifest-keys mode), then the form (`is_active_document_form`, on the raw value), then the walk (`_walk_manifest_entry`). Each refusal stops at its step, so one refused value gives `None` and exactly 1 issue.
- `active_document` is parsed first, right after `active_variant` and before `batch`. So its folder check is never past `MANIFEST_FOLDER_CHECK_CAP`, its finding is never folded by `_bound_entry_findings`, and the `files` key of the same text costs 0 new filesystem calls (the walk cache).
- The `files` exception is an exact text match: a `files` key whose raw text equals the accepted `active_document` skips the O-2 scope rule (it still gets the text rules, the walk and the record checks). `derived_from` gets no exception.

### Design risks

**R1 — seam A/B: a document name that fails the form makes the whole save fail (HIGH for E3).** LLR-170.1 says `serialize_manifest` refuses the whole serialize for a value outside the form. Two app paths can produce such a value:
- a file-backed document whose name does not end in exactly `.json`. The gather places it under its own name (`project_gather_service.py:497-507`), and `changes/io.py::_safe_name` keeps `.JSON` as it is (its suffix test is case-insensitive). So `patches/boost.JSON` or `patches/boost.txt` can reach the writer.
- a file-backed document already inside the project but not directly in a home: `P/boost.json`, `P/patches/sub/x.json`, `P/flows/x.json`. The gather skips it (`is_relative_to(resolved_project)`), so it is not moved into a home. (E3 R11: the gather classifier calls it `inside_elsewhere`, decided on the unresolved text; it gets 0 plan rows and is not recorded.)

In both cases, Save project would end with the manifest refused. RESOLVED by pre-ruling 2 and 1: the app checks a landing with `is_active_document_form` before it records it (a landing that fails records nothing and keeps one status line), and the suffix is compared case-insensitively, so `patches/boost.JSON` is accepted. The reader side is safe either way (it refuses and reads the rest).

**R2 — seam B: `str` against `Path` keys (MEDIUM).** `ProjectManifest.active_document` is text; `ProjectManifest.files` is keyed by `project_dir.resolve() / parts` (the walk's path, not `.resolve()` of the file). `check_project_files` must report a missing recorded document exactly once, "with and without a `files` record" (LLR-169.5; LLR-170.3's negative control: 2 problems for one file → RED). Group B must build the comparison key the same way as the reader, `project_dir.resolve().joinpath(*text.split("/"))`, not `project_dir / text` (unresolved) and not `.resolve()` of the file (which follows a link and changes case on Windows). `verify_written_manifest` (LLR-169.3) compares `manifest.active_document` with the intended value as text, so the intended value must be the same POSIX text, never a `Path`.

**R3 — seam A: the reopen uses a checked text, later (LOW, for the security reviewer).** The reader checks the document with `os.lstat` per component (a link or junction at `patches` or at the file → refused). The reopen (`_handle_load_project`, group A) opens the file later. If a link appears between the read and the open, the open follows it. Inc 7 has the same gap for the images (`files` paths). The reopen must join `project_dir` with the text (never accept an absolute path from elsewhere). E3 R10: the reopen and Save project both read through the app's one classifier `recorded_document_state` (two `os.lstat`, the 1 MiB cap, one bounded read, a guarded decode and count, then the parse of those bytes), not through `ChangeService.load`; the `lstat` → open window stays the class pre-ruling 11 accepted.

**R4 — Inc 7 rules: what changes and what does not.**
- **SEC6-2 (unknown-key refusal) — unchanged for older manifests.** A manifest without `active_document` reads exactly as at `dc3b314`. A manifest with another unknown key (`future_key`, the TC-B100-07 / TC-B100-20 matrix) is still refused. The only manifests that change are the ones holding `active_document`. With a valid value, they are now carried (the requirement). With a refused value, the key is known, so `unknown_keys` does not hold it, but the refusal adds 1 issue. So `manifest_rewrite_refusal` → "holds entries that were skipped", and the rewrite is still refused, never carried verbatim. SEC6-2's "never dropped silently" holds.
- **Save project and a refused value (E3 R5).** A refused `active_document` is a skipped entry, and `manifest_keep_reason` now fires for it, so Save project keeps `project.json.previous-<UTC>` (SEC7-3) and the status names the copy and the dropped value. The E2 text said the Load panel showed the refused value first; that is false for a merge, because the merge target is never loaded (S3-6). A skipped `batch` entry keeps its Inc 7 behaviour (no copy).
- **Downgrade (not a requirement).** An Inc 7 build reading an 8a manifest sees `active_document` as unknown, refuses the in-project rewrites, keeps a `.previous` copy on Save project, and lists the document's `files` key as 1 `manifest damaged` row. That is the safe direction.
- **Caps, text-first, `_EntryWalk` exact-text cache, folder ceiling, 32-component depth, link/junction final file refused, overlong decided on the text:** all reused unchanged through `_entry_text` and `_walk_manifest_entry`. `active_document` is a scalar, so `_over_cap_issues` does not count it. The 1 MiB cap covers it. The per-read cost grows by at most 2 `os.lstat` calls (`patches`, then the file) and one text pass of ≤ 32 767 characters.
- **SEC6-5 bound:** the refusal finding carries `_entry_mark`, so it counts as one of the ≤ 100 skipped-entry rows. Because the document is parsed first, its row is always kept, never folded.

**R5 — outside reader `execute_project_variants` → Execute status lines (LOW).** `_report_execution_results` (`app.py:4887`) paints every manifest issue as one status line on each Execute. After 8a, an app-written manifest gives 0 lines for the document. At `dc3b314` a hand-made manifest with a `patches/…` `files` key gave 1 `MANIFEST-BAD-STRUCTURE` line. A hand-made refused `active_document` gives 1 line on each Execute. The active document is not added to the execution plan: `plan_variant_executions` reads only `batch` and `assignments`. AT-B100-20's "the batch documents in the Execute-scope list" is about `batch`, not the active document. Group A must not assume that Execute runs the reopened document through the manifest.

**R6 — `_missing_recorded` can name the document (LOW, outside the slice, same file). JOINS 8a (pre-ruling 12, E3 R7; requirement arm in LLR-169.5).** `_missing_recorded` (`variant_execution_service.py:1910`) names a missing recorded variant by the first `files` key whose stem or name equals the id, excluding only MAC and A2L suffixes. With `active_variant` `"boost"` missing and a `files` key `patches/boost.json` listed before `boost.s19` (or with no `boost.s19` record), the Load summary names `boost.json`. This was unreachable before 8a, because the reader refused every sub-folder key. Fix: restrict the match to `PROJECT_PRIMARY_DATA_EXTENSIONS`; see the node `_missing_recorded`.

**R7 — `_relation_line` (OBS-7-1), checked: no effect.** It matches `files` keys by `path.name == record.base`, and `base` is one top-level data name (never `.json`). A document key cannot match.

### Proposed changes to interfaces-8a.md

**P1 — the home set cannot come from `document_home_for_kind` at run time.** `project_gather_service.py:79` imports `variant_execution_service` at module level, so `variant_execution_service` cannot import `document_home_for_kind` or `PROJECT_PATCHES_DIR` / `PROJECT_CHECKS_DIR` without an import cycle. Proposal: a module constant `ACTIVE_DOCUMENT_HOMES = frozenset({"patches", "checks"})` in `variant_execution_service.py`, plus one test pinning `ACTIVE_DOCUMENT_HOMES == {document_home_for_kind("change"), document_home_for_kind("check")}`. That test is the negative control for drift between the two homes. The alternative, moving the three home constants to `workspace.py`, touches more files. Not recommended.

**P2 — the suffix rule and R1 need one decision.** The interface says the second component ends in `.json`. Read literally, that is case-sensitive, and that is what this graph does (`patches/boost.JSON` → `False`). Because of R1, E3 should choose one of two options:
- (a) keep it case-sensitive, and make group A not record (one status line) a document whose landed project-relative name fails the predicate;
- (b) make the suffix test case-insensitive, as `_safe_name` does, and still apply (a) to other suffixes and to documents outside a home.

Recommendation: (b) + (a). Either way, the predicate stays the one rule at both ends.
DECIDED (pre-ruling 1): option (b) + (a). The home component is exact lowercase, the `.json` suffix is compared case-insensitively, and the app records nothing for a landing that fails the form.

**P3 — the predicate is total.** Contract `is_active_document_form(text: str) -> bool`, but it returns `False` for any value that is not a `str` and never raises. Reason: the predicate has four callers in three groups (the reader on a raw JSON value, the writer, the gather's `document_in_home`, the app before it records a landing), and the reader's raw value can be any JSON type; a `Path` or a number passed by mistake would raise `TypeError` in `"\\" in text`. With this rule, it is refused as a finding instead. (A3R2-9: `GatherOutcome.active_document` is now project-relative text, `Optional[str]`, pre-ruling 3; it is no longer the reason.)

**P4 — issue codes per refusal, for the parallel tester (E4).** The interface says only "a refusal adds one issue". Proposal: write the codes into the interface. Text rules → their existing code (non-string, empty or blank → `BS`; overlong, more than 32 components, drive / root / `:` / device / trailing dot or space, `..` climbing out, NUL → `PE`). Out of form → `BS`. Link or junction on the walk → `PE`. This mirrors `_recorded_file` for `files` keys (LLR-169.4: `../x.s19` → `PE`, `sub/x.s19` → `BS`).

**P5 — explicit `null` (decision to confirm, no signature change).** `"active_document": null` reads as absent: `None`, 0 issues. This follows the precedent of `active_variant` at `variant_execution_service.py:1342`. The writer never emits `null`. The other choice (1 `BS`) would make a `null` block every in-project rewrite.
**P6 — control characters (E3 R6, S3-7).** The predicate also refuses any C0 or C1 control character (code below 0x20, or 0x7F to 0x9F) anywhere in the text. Reason: the recorded text is untrusted and is painted; `_manifest_key_refusal` admits them. The reader answers one `MANIFEST-BAD-STRUCTURE`; the writer answers one finding.

### Outside readers of `read_project_manifest` (baseline-notes §2)

| Reader | What it reads | With `active_document` and the document's `files` key | Breaks? |
|---|---|---|---|
| `S19TuiApp._trigger_execute_scope` (`app.py:4751`) | `is not None` only | ignores both | no |
| `S19TuiApp._trigger_generate_report` (`app.py:5225`) | `is None` only | ignores both | no |
| the report worker in `_trigger_generate_report` (`app.py:5333`, then `execute_project_variants` at `:5336`) | `is not None`; the returned issues are discarded (`_manifest_issues`) | ignores both | no |
| `execute_project_variants` (`variant_execution_service.py:2453`) | `batch`, `assignments` (through `plan_variant_executions`) and `issues` (returned, then painted by `_report_execution_results`) | the plan is unchanged; `issues`: the document's `files` key gives 0 issues now (1 `BS` at `dc3b314`); a refused `active_document` gives 1 issue → 1 status line per Execute (R5) | no; the status line count changes only for hand-made manifests |

The in-slice readers (`_handle_save_dialog` at `app.py:9272`, `_handle_load_project` at `:10510`, `_rewrite_project_manifest` at `:10789`, `verify_written_manifest` and `check_project_files` in `manifest_writer.py`) are groups A and B. Their needs are the seams R1–R3.

## Nodes

is_active_document_form
req: LLR-170.1
in: str text
out: bool ok
func: NEW. The one form predicate for `active_document` (S-11), pure text, no filesystem call, never raises. True only for a str of at most MANIFEST_ENTRY_MAX_CHARS characters with no backslash, no ":", no NUL, no C0 or C1 control character (E3 R6), no leading "/", whose "/" split is exactly [home, name]: home in ACTIVE_DOCUMENT_HOMES ("patches", "checks"; P1; compared exactly, lowercase), name not "", "." or "..", name ends ".json" with a non-empty stem (the suffix compared case-insensitively, pre-ruling 1). Used by the reader (on the raw value), by manifest_writer.serialize_manifest (group B, with _reject_unsafe_entry), by the gather's `document_in_home` and by the app before it records a landing.
module: s19_app/tui/services/variant_execution_service.py
examples: (TC-B100-28, LLR-170.1 round-trip) text "patches/boost.json" → ok `True`; text "checks/c.json" → ok `True`
examples: (TC-B100-29, the M-1 landing names) text "patches/changes.json" → ok `True`; text "patches/changes_1.json" → ok `True`
examples: (TC-B100-28 writer arm) text "firmware.s19" → ok `False`; text "../x.json" → ok `False`
examples: (TC-B100-28 reader arm) text "project.json" → ok `False`; text "patches/x.txt" → ok `False`; text "/abs/x.json" → ok `False`
examples: (interfaces-8a "no backslash") text "patches\\boost.json" → ok `False`
examples: (interfaces-8a "exactly two components") text "boost.json" → ok `False`; text "patches/sub/x.json" → ok `False`; text "patches/../x.json" → ok `False`; text "./patches/x.json" → ok `False`
examples: (interfaces-8a "a document home") text "templates/t.json" → ok `False`; text "flows/f.json" → ok `False`
examples: (interfaces-8a "no drive") text "C:patches/x.json" → ok `False`; text "C:/patches/x.json" → ok `False`
examples: (CI-6-1 bound, MANIFEST_ENTRY_MAX_CHARS `32767`) "patches/" + 32 754 × "a" + ".json" (32 767 characters) → ok `True`; one more "a" (32 768) → ok `False`
examples: (design choice, E3) text "patches/.json" → ok `False`; text " patches/boost.json" → ok `False`; text "patches/boost.json " → ok `False`; text "Patches/boost.json" → ok `False` (the writer only writes the lowercase homes; the home is compared exactly)
examples: (pre-ruling 1, S3-12) text "patches/boost.JSON" → ok `True`; text "patches/boost.Json" → ok `True` (the suffix is compared case-insensitively; the home stays exact)
examples: (P3, design choice, E3) a non-str value `7`, `True`, `None`, a list ["patches/boost.json"] or a Path → ok `False`, no raise
examples: (E3 R6, S3-7) text "patches/" + ESC + "]0;x" + BEL + "a.json" (C0 control characters) → ok `False`; text "patches/a" + chr(0x85) + ".json" (a C1 control character) → ok `False`; text "patches/a" + chr(0x7F) + ".json" → ok `False`
examples: (E3 R6 negative control) a mutation without the control-character check → the ESC text is accepted, `True` → RED

_parse_manifest_active_document
req: LLR-170.1, LLR-169.4
in: object raw; list[ValidationIssue] issues; _EntryWalk walk
out: Optional[str] active_document
func: NEW (reader arm, by analogy with _parse_manifest_derived_from and _recorded_file). raw None (key absent or JSON null, P5) → None, 0 issues. Else: (1) _entry_text(raw, "active_document", issues, ENTRY_MODE_MANIFEST_KEYS) → None ends here (1 issue, its own code); (2) is_active_document_form(raw) on the raw value (so a stripped space never changes the recorded text) → False appends 1 MANIFEST-BAD-STRUCTURE with _entry_mark(raw) and ends (a control character ends here too, E3 R6); (3) _walk_manifest_entry(walk, text, "active_document", issues) → None ends (1 MANIFEST-PATH-ESCAPE). Accepted → the raw text unchanged. A document absent from disk is accepted (the walk stops at the missing component); check_project_files owns `missing` (LLR-169.5). The issue carries the context "active_document", which `manifest_keep_reason` reads (E3 R5).
module: s19_app/tui/services/variant_execution_service.py
modify: issues (append)
examples: (TC-B100-28) raw "patches/boost.json", file on disk → active_document "patches/boost.json", issues `0`
examples: (TC-B100-28) raw "checks/c.json", file on disk → active_document "checks/c.json", issues `0`
examples: (TC-B100-28 reader arm 1/6) raw "../x.json" → active_document `None`, 1 issue "MANIFEST-PATH-ESCAPE" (text: climbs above the project)
examples: (TC-B100-28 reader arm 2/6) raw "/abs/x.json" → active_document `None`, 1 issue "MANIFEST-PATH-ESCAPE" (text: a root)
examples: (TC-B100-28 reader arm 3/6) raw `7` → active_document `None`, 1 issue "MANIFEST-BAD-STRUCTURE" with entry mark "7"
examples: (TC-B100-28 reader arm 4/6) raw "firmware.s19" → active_document `None`, 1 issue "MANIFEST-BAD-STRUCTURE" (form)
examples: (TC-B100-28 reader arm 5/6) raw "project.json" → active_document `None`, 1 issue "MANIFEST-BAD-STRUCTURE" (form)
examples: (TC-B100-28 reader arm 6/6) raw "patches/x.txt" → active_document `None`, 1 issue "MANIFEST-BAD-STRUCTURE" (form)
examples: (design choice, E3: the other non-string types) raw `True` → `None`, 1 issue "MANIFEST-BAD-STRUCTURE" with entry mark "true"; raw ["patches/boost.json"] → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw {} → `None`, 1 issue; raw "" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (interfaces-8a form) raw "patches\\boost.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw "boost.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw "patches/sub/x.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw "templates/t.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (LLR-169.8 manifest-keys mode) raw "C:patches/x.json" → `None`, 1 issue "MANIFEST-PATH-ESCAPE"; raw "patches/NUL.json" → `None`, 1 issue "MANIFEST-PATH-ESCAPE"; raw "patches/x.json." → `None`, 1 issue "MANIFEST-PATH-ESCAPE"; raw "patches/a:b.json" → `None`, 1 issue "MANIFEST-PATH-ESCAPE"
examples: (CI-6-1) raw of 32 768 characters → `None`, 1 issue "MANIFEST-PATH-ESCAPE" before any filesystem call (walk.folder_calls `0`)
examples: (SEC7-1 32-component rule) raw "patches/" + 32 × "a/" + "x.json" → `None`, 1 issue "MANIFEST-PATH-ESCAPE" (text rule, before the form)
examples: (Inc 7 accepted cp1 behaviour, link refused) `patches` is a junction → `None`, 1 issue "MANIFEST-PATH-ESCAPE" with reason "a file path goes through a link or junction"; `patches/boost.json` is a symbolic link → `None`, 1 issue "MANIFEST-PATH-ESCAPE"
examples: (LLR-170.3 / LLR-169.5 missing arm) raw "patches/boost.json", file deleted → active_document "patches/boost.json", issues `0`
examples: (design choice, E3: the raw value is checked) raw " patches/boost.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw "patches/boost.json " → `None`, 1 issue "MANIFEST-PATH-ESCAPE" (trailing space, text rule)
examples: (P5, design choice, E3) raw `None` (key absent or JSON null) → `None`, issues `0`
examples: (pre-ruling 1) raw "patches/boost.JSON", file on disk → active_document "patches/boost.JSON", issues `0`; raw "Patches/boost.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (E3 R6, S3-7) raw "patches/" + ESC + "]0;x" + BEL + "a.json" → active_document `None`, 1 issue "MANIFEST-BAD-STRUCTURE", the file is never looked up (walk.folder_calls `0`)
examples: (SEC7-1 cost) raw "patches/boost.json" first in the read → walk.folder_calls `1`, 2 os.lstat calls in all

_recorded_file
req: LLR-169.4
in: object raw_key; str context; list[ValidationIssue] issues; _EntryWalk walk; Optional[str] document = None
out: Optional[Path] path
func: CHANGED. New parameter `document`: the accepted active_document text, or None. After the text rules, a raw_key that is a str exactly equal to `document` skips the O-2 scope rule (top-level data or A2L name) and goes to the walk. Any other key keeps the scope rule, so every key under a document home that is not the document gives 1 MANIFEST-BAD-STRUCTURE. Equality is on the raw text: no case folding, no separator mapping, no strip.
module: s19_app/tui/services/variant_execution_service.py
modify: issues (append)
examples: (TC-B100-24 Inc 8a arm) raw_key "patches/boost.json", context "files", document "patches/boost.json" → path <ROOT>/patches/boost.json, issues `0`
examples: (TC-B100-24 Inc 8a arm) raw_key "patches/other.json", context "files", document "patches/boost.json" → path `None`, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (LLR-169.4 "and not active_document"; refused document) raw_key "patches/boost.json", document `None` → path `None`, 1 issue "MANIFEST-BAD-STRUCTURE" (holds at dc3b314)
examples: (design choice, E3: exact text) raw_key "patches\\boost.json", document "patches/boost.json" → path `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw_key "Patches/boost.json" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (TC-B100-24, holds at dc3b314) raw_key "patches/NUL.json", document "patches/boost.json" → path `None`, 1 issue "MANIFEST-PATH-ESCAPE" (text rules run first); raw_key "sub/x.s19" → `None`, 1 issue "MANIFEST-BAD-STRUCTURE"; raw_key "firmware.s19" → path <ROOT>/firmware.s19
examples: (SEC7-1 exact-text cache) raw_key "patches/boost.json" after the document was walked → 0 new os.lstat calls

_parse_manifest_files
req: LLR-169.4, LLR-169.2
in: object raw; list[ValidationIssue] issues; _EntryWalk walk; Optional[str] active_document = None
out: dict[Path, FileRecord] records
func: CHANGED. Passes `active_document` to _recorded_file as `document` for every key. Record checks (size int ≥ 0, never bool; sha256 64 lowercase hex) unchanged and applied to the document's record too.
module: s19_app/tui/services/variant_execution_service.py
modify: issues (append)
examples: (TC-B100-22 / TC-B100-28 A-15 arm) raw holds "firmware.s19", "firmware.mac", "firmware.a2l", "prg.srec" and "patches/boost.json", active_document "patches/boost.json" → records `5`, issues `0`
examples: (TC-B100-22 A-15 arm, other.json never recorded by the writer) the same plus a hand-added "patches/other.json" → records `5`, 1 issue "MANIFEST-BAD-STRUCTURE" naming "patches/other.json"
examples: (design choice, E3: a refused document refuses its key) the A-15 raw, active_document `None` (refused upstream) → records `4`, 1 issue "MANIFEST-BAD-STRUCTURE" naming "patches/boost.json"
examples: (TC-B100-24, record checks unchanged) key "patches/boost.json" accepted by text, value size `True` → no record for it, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (LLR-169.2 missing-document arm, the writer writes no record) raw with the 4 top-level files only, active_document "patches/boost.json" → records `4`, issues `0`

_parse_manifest_derived_from
req: LLR-168.4, LLR-169.4
in: object raw; list[ValidationIssue] issues; _EntryWalk walk
out: dict[Path, DerivedFrom] records
func: NO CHANGE. Calls _recorded_file with no document, so the exception stays limited to `files`. Included as the negative control for the scope of the exception.
module: s19_app/tui/services/variant_execution_service.py
modify: issues (append)
examples: (design choice, E3: `files` only) raw {"patches/boost.json": a valid record}, active_document "patches/boost.json" in the same manifest → records `0`, 1 issue "MANIFEST-BAD-STRUCTURE"

read_project_manifest
req: LLR-170.1, LLR-169.4, LLR-169.2, LLR-168.3
in: Path project_dir; Optional[SizeProbe] size_probe = None
out: Optional[ProjectManifest] manifest
func: CHANGED. After active_variant and before batch: active_document = _parse_manifest_active_document(payload.get("active_document"), issues, walk). Then _parse_manifest_files(..., active_document). ProjectManifest gets active_document. unknown_keys no longer holds "active_document" (KNOWN_MANIFEST_KEYS). Every early return (size cap, JSON parse, non-object, over-cap) leaves active_document None. Caps, the walk, the ceiling and _bound_entry_findings are unchanged.
module: s19_app/tui/services/variant_execution_service.py
examples: (TC-B100-28) a manifest with active_variant "firmware" and active_document "patches/boost.json" → manifest.active_document "patches/boost.json", manifest.active_variant "firmware", unknown_keys `()`, issues `0`
examples: (TC-B100-28 reader arms) each of "../x.json", "/abs/x.json", `7`, "firmware.s19", "project.json", "patches/x.txt" as active_document, with active_variant "firmware" → active_document `None`, 1 issue, active_variant "firmware" (6 of 6)
examples: (TC-B100-28 absent arm) no active_document key → active_document `None`, issues `0`
examples: (TC-B100-28 A-15 + TC-B100-24 Inc 8a arm) the app-written P (4 top-level files, active_document "patches/boost.json" and its `files` record) → files `5`, issues `0`
examples: (TC-B100-24 Inc 8a arm) the same P with a `files` key "patches/other.json" added → files `5`, 1 issue "MANIFEST-BAD-STRUCTURE"
examples: (design choice, E3: a refused document refuses its `files` key) P with active_document `7` and the "patches/boost.json" record → active_document `None`, files `4`, 2 issues
examples: (SEC6-5 + parse order, design choice, E3) 1 001 escaping batch entries and active_document "patches/x.txt" → the active_document finding is kept one by one and the fold finding counts the batch rest; read under 1 s
examples: (R2-2 ceiling + parse order) a manifest whose batch needs 1 000 distinct folder checks and active_document "patches/boost.json" → active_document "patches/boost.json" (walked first, never unchecked)
examples: (LLR-169.4 size cap, holds at dc3b314) a 1 MiB + 1 byte project.json holding active_document → 1 issue "MANIFEST-SIZE-CAP", active_document `None`
examples: (SEC6-2, holds at dc3b314) a manifest with "future_key" → unknown_keys ("future_key",)

manifest_keep_reason
req: LLR-168.3, SEC7-3, LLR-170.1
in: ProjectManifest manifest
out: Optional[str] reason
func: CHANGED (E3 R5, S3-6). Besides the unknown keys, it returns a reason when the manifest holds a REFUSED `active_document`: any issue whose context is "active_document" (the reader's issue for a refused value) gives the reason "holds a change document path this version cannot use". Reason: a merge target is never loaded, so no panel row ever shows the refusal, and Save project would drop the key silently. Save project (group A) keeps `project.json.previous-<UTC>` and its status names the copy and the dropped value. A skipped `batch` entry or a skipped `files` entry is not a keep reason (Inc 7 behaviour, unchanged).
module: s19_app/tui/services/variant_execution_service.py
examples: (TC-B100-05 Inc 8a merge arm) a target manifest with a valid active_document "patches/boost.json" → reason `None`, no kept copy (at dc3b314 → "holds keys this version does not know")
examples: (SEC7-3, holds at dc3b314) a manifest with "future_key" → reason "holds keys this version does not know"
examples: (E3 R5, S3-6) a target manifest with active_document "templates/x.json" (refused by the reader) → reason "holds a change document path this version cannot use"; a manifest with active_document `7` → the same reason
examples: (E3 R5 negative control) a mutation ignoring the refused value → reason `None` → no kept copy → RED
examples: (Inc 7, unchanged) a manifest with 1 skipped `batch` entry and no refused active_document → reason `None`

manifest_rewrite_refusal
req: LLR-168.3, LLR-170.1
in: ProjectManifest manifest
out: Optional[str] reason
func: NO CODE CHANGE. Decides whether the four in-project writers carry a manifest that holds active_document.
module: s19_app/tui/services/variant_execution_service.py
examples: (AT-B100-20, LLR-170.1 variant-append arm) batch, assignments, declared_regions, gathered and active_document "patches/boost.json" all set → reason `None`
examples: (SEC6-2 kept for a refused value) the same manifest with active_document "patches/x.txt" → reason "holds entries that were skipped"
examples: (SEC6-2, holds at dc3b314) a manifest with "future_key" → reason "holds keys this version does not know"
examples: (SEC6-2, older manifests unchanged) a manifest without active_document and with no issue → reason `None`

execute_project_variants
req: LLR-168.3
in: Path project_dir; ProjectVariantSet variant_set; str scope = SCOPE_ALL; Sequence[Path] fallback_batch = (); Optional[StatusCallback] status_callback = None; bool capture_mem_maps = False
out: tuple(list[VariantExecutionResult] results, list[ValidationIssue] manifest_issues)
func: NO CHANGE (outside reader). The plan reads batch and assignments only; manifest.issues are returned and painted by _report_execution_results. The active document is not run through the manifest.
module: s19_app/tui/services/variant_execution_service.py
examples: (AT-B100-20 Execute-scope arm) the app-written P with active_document "patches/boost.json", its `files` record and batch ["patches/a.json"] → manifest_issues `0`, each variant's planned files ("patches/a.json" only)
examples: (R5, design choice, E3) a hand-made P with active_document `7` → manifest_issues 1 "MANIFEST-BAD-STRUCTURE" (1 status line per Execute)

_missing_recorded
req: LLR-169.5, LLR-169.6
in: str variant_id; ProjectManifest manifest
out: Optional[str] name
func: CHANGED (E3 R7, pre-ruling 12; the requirement arm is in LLR-169.5). Names the data file of a missing recorded variant: the first `files` key whose stem or name equals the id, now restricted to `PROJECT_PRIMARY_DATA_EXTENSIONS` (before: all suffixes except MAC and A2L). A document key such as `patches/boost.json` is never a data file, so it is never named. No such key → the variant id itself.
module: s19_app/tui/services/variant_execution_service.py
examples: (LLR-169.5 E3 R7 arm) variant id "boost" missing, `files` holds "patches/boost.json" (the active document) and "boost.s19" → name "boost.s19", never "boost.json"
examples: (LLR-169.5 E3 R7 arm) variant id "boost" missing, `files` holds only "patches/boost.json" → name "boost" (the id)
examples: (LLR-169.5 E3 R7 holds) variant id "fw" missing, `files` holds "fw.s19" → name "fw.s19" (holds at dc3b314)
examples: (LLR-169.5 E3 R7 negative control) a mutation dropping the suffix restriction → the first arm names "boost.json" → RED

## Entities

[Data: KNOWN_MANIFEST_KEYS]
in: frozenset[str]
desc: CHANGED. The 8 keys at dc3b314 plus "active_document" (9). Read by read_project_manifest for unknown_keys, which manifest_keep_reason and manifest_rewrite_refusal read (SEC6-2). LLR-170.1's negative control: the key left out → the variant append refuses the rewrite → RED.

[Data: ProjectManifest.active_document]
in: Optional[str]
desc: NEW field, declared last with default None (the dataclass is slots=True, and the fields before it have defaults; the 18 keyword-argument constructors in tests and source stay valid). The project-relative POSIX text exactly as written in project.json, or None when absent, JSON null or refused. Consumers join it with project_dir.resolve() by its "/" parts (R2); never a Path, never absolute.
sequence:
  read: _parse_manifest_active_document wins → _parse_manifest_files (reads the accepted text for the `files` exception)

[Data: ProjectManifest.files]
in: dict[Path, FileRecord]
desc: UNCHANGED type. From 8a it can hold one key under a document home: the active document, keyed <ROOT>/<home>/<name> (the walk's path).

[Data: _EntryWalk]
in: _EntryWalk
desc: UNCHANGED. One per read. Parsing active_document first makes its folder check call 1 of at most MANIFEST_FOLDER_CHECK_CAP, and its cache entry serves the equal `files` key.

## Edges

[Data: ProjectManifest.active_document] ──▶ _parse_manifest_files
[Data: KNOWN_MANIFEST_KEYS] ──▶ read_project_manifest
