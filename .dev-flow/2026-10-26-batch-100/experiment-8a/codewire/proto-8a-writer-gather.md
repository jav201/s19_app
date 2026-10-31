# Code-Wire prototype — Inc 8a, group B (`manifest_writer.py`, `project_gather_service.py`)

Step E2 of `../PLAN.md`. Graph only: no stub, mark or other change in `s19_app/` (orchestrator correction, operator ruling). New functions and fields are graph nodes or entities whose `func:` / `desc:` starts with "new". Interfaces are those of `interfaces-8a.md`; my changes to them are in "Proposed changes" at the end.

Example sources: the TC/AT thresholds of `01-requirements.md` (after LED .72) and the Inc 7 rulings in `03-increments/increment-007.md` §6. Each example says "target (8a)" (the requirement asks for it, it does not hold at `dc3b314`) or "holds" (behaviour 8a must keep). Paths are project-relative POSIX text unless a line says "absolute". `is_active_document_form` is group C's predicate (interfaces-8a.md); I use it as a callee.

**Counts:** 10 function nodes (7 changed: `serialize_manifest`, `write_project_manifest`, `verify_written_manifest`, `project_file_records`, `check_project_files`, `gather_project_artifacts`, `plan_project_save`; 3 new: `_active_document_missing`, `document_in_home`, `classify_active_document`), 6 entities (data), 3 design findings. Every owned LLR has at least one example: 170.1, 170.2, 167.6, 164.2, 169.2, 169.3, 169.5 (and 169.4's scope at the writer, P-B3). E3 round 1 (2026-10-30) applied: the rulings R1-R7 of `../E3-rulings.md` and the prototype edits A3-1, A3-6, A3-9, A3-12, A3-14 (a, b, c), S3-8, S3-11, S3-12. The `replace` action and the in-place rewrite are removed (R1); the document row's actions are `new` and `keep`. One problem text everywhere: `patches/boost.json`; `GatherOutcome.active_document: Optional[str]`; `PlannedFile.home: Optional[str]`.

E3 round 2 (2026-10-30) applied: R11 (one gather classifier `classify_active_document`, classes `in_home` / `outside` / `inside_elsewhere` / `missing`, used by `plan_project_save` and `gather_project_artifacts`; "inside" decided on the unresolved text; the source `lstat`-ed, a link is never copied), R8 refined (Save project drops a carried value only on the app classifier's `missing`, `link` or `unreadable`), A3R2-1, A3R2-2 (items 7), A3R2-5 (entities `PlannedFile.source` and `PlannedFile.role`, the module-comment note, TC-B100-23's "holds" example restored from `baseline-8a.md`), A3R2-6, A3R2-7 (the home component compared exactly) and S3R2-5.

## Nodes

serialize_manifest
req: LLR-170.1, LLR-169.1, LLR-169.4, LLR-168.4
in: ProjectVariantSet variant_set; Path project_root; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; int schema_version = DEFAULT_SCHEMA_VERSION; Optional[str] active_document = None
out: tuple[Optional[str], list[ValidationIssue]] result
func: changed. New keyword `active_document`. When it is not None: first `is_active_document_form(text)` on the text alone (no filesystem call; it also refuses C0/C1 control characters, E3 R6); when that is False, exactly one MANIFEST-WRITE-ESCAPE finding naming `active_document` and the predicate walk is NOT run (so one value gives one finding). When the form passes, `_reject_unsafe_entry(project_root, text, "active_document", walk)` with the serialize's ONE `_EntryWalk` (SEC7-R2-2), so a link or junction on the way or as the final file refuses it. The document is checked FIRST in that walk, before `files`, `gathered` and the other entries, so its folder check is never past `MANIFEST_FOLDER_CHECK_CAP` (S3-11); the key is still emitted LAST (check order is not emit order), which keeps the reader's rule (the document is parsed first) and the writer symmetric at the ceiling edge. A `files` key with more than one component is refused unless its text equals `active_document` (pre-ruling 4, P-B3). Any finding → `(None, findings)`, no text (the existing all-or-nothing rule). On success the key is emitted verbatim (no separator rewrite: the predicate already refused a backslash) as the LAST key, after `derived_from`, so every manifest without the key stays byte-identical. `None` → no key. Existence and readability on disk are not checked (the reader's walk does not check them either), so a carried key whose file was deleted would still be written; Save project (group A) drops it before the call when the app's classifier says `missing`, `link` or `unreadable` and keeps it for `too_large` and `io_error` (E3 R2, R8 refined), and a carry writer keeps it as recorded and Load reports it.
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-28) active_document "patches/boost.json" → text holds `"active_document": "patches/boost.json"`, issues `0`; read back by read_project_manifest → active_document "patches/boost.json" (target (8a))
examples: (TC-B100-28) active_document "checks/c.json" → text holds "checks/c.json", read back equal (2 of 2 round-trips) (target (8a))
examples: (TC-B100-28) active_document `None` → text has no "active_document" key and is byte-identical to the output of the same call without the keyword (target (8a); byte identity holds for every 1d677ba pin, TC-B100-21)
examples: (TC-B100-28 writer arm) active_document "firmware.s19" → result `None` text, findings `1` naming "active_document" (target (8a))
examples: (TC-B100-28 writer arm) active_document "../x.json" → `None` text, findings `1` (form refusal; the walk is not run) (target (8a))
examples: (LLR-170.1 form, interfaces-8a) active_document "patches\\boost.json" (a backslash) → `None` text, findings `1` (target (8a))
examples: (LLR-170.1 form) active_document "patches/sub/boost.json" (three components) → `None` text, findings `1` (target (8a))
examples: (LLR-170.1 form) active_document "patches/boost.txt" → `None`, findings `1`; "templates/t.json" (a home that is not a document home) → `None`, findings `1` (target (8a))
examples: (LLR-170.1 form) active_document "C:patches/boost.json" (drive-relative) and "C:/x.json" → `None` text, findings `1` each (target (8a))
examples: (LLR-170.1 form, CI-6-1 bound) active_document "patches/" + 32 763 characters + ".json" (32 777 > MANIFEST_ENTRY_MAX_CHARS `32767`) → `None`, findings `1`, decided on the text (target (8a))
examples: (LLR-170.1 via _reject_unsafe_entry, LLR-169.4 hostile set) active_document "patches/NUL.json" → `None` text, findings `1` (target (8a))
examples: (Inc 7 accepted cp1 behaviour "a link or junction as the final file is refused") `P/patches/boost.json` is a junction or symlink, active_document "patches/boost.json", files without a record for it → `None` text, findings `1`; 0 bytes written by the caller (target (8a))
examples: (Inc 7 cp1 "link on the way") `P/patches` is a junction to a folder outside P, active_document "patches/boost.json" → `None` text, findings `1` (target (8a))
examples: (LLR-170.1, SEC7-R2-2) a manifest with 31 folder entries plus active_document → one `_EntryWalk` for the call (the document's `patches` folder is looked up once even when `gathered` also names "patches/boost.json") (target (8a); the one-walk rule holds)
examples: (LLR-170.1 + LLR-169.2) active_document "patches/boost.json" and files holding "patches/boost.json" → text holds both; files key "patches/boost.json" is checked by the existing files loop (target (8a))
examples: (P-B3, pre-ruling 4) `files` holding a key "patches/other.json" and active_document "patches/boost.json" → `None` text, findings `1` (target (8a)); negative control: the check dropped → the manifest is serialized and the reader refuses it → RED
examples: (pre-ruling 1) active_document "patches/boost.JSON" → text holds it, issues `0` (the suffix is compared case-insensitively); "Patches/boost.json" → `None` text, findings `1` (target (8a))
examples: (E3 R6, S3-7) active_document "patches/" + ESC + "]0;x" + BEL + "a.json" (C0 control characters) → `None` text, findings `1` (target (8a))
examples: (S3-11, R2-2 ceiling) entries needing 1 000 folder checks plus active_document "patches/boost.json" → the document is walked first, accepted; the text holds it, issues `0`; the reader accepts the same text (target (8a))

write_project_manifest
req: LLR-170.1, LLR-169.7
in: ProjectVariantSet variant_set; Path project_root; Path base_dir; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; int schema_version = DEFAULT_SCHEMA_VERSION; Optional[str] active_document = None
out: tuple[Optional[Path], list[ValidationIssue]] result
func: changed. Passes `active_document` through to serialize_manifest. Nothing else changes: a refused serialize still returns before `ensure_workarea`, before the private stage directory exists and before `os.replace` (LLR-169.7 private staging, SEC7-2 re-check after the replace, SEC7-R2-3 message without the exception class all unchanged).
module: s19_app/tui/services/manifest_writer.py
modify: [I/O: project.json] (replace)
examples: (TC-B100-28) active_document "patches/boost.json" → path ends "project.json", issues `0`; the file holds "patches/boost.json" (target (8a))
examples: (TC-B100-28 writer arm, refusal writes 0 bytes) a P with an existing project.json, active_document "firmware.s19" → path `None`, findings `1`; project.json bytes unchanged (0 bytes written), 0 directories left under `.s19tool/workarea/temp/` (target (8a))
examples: (TC-B100-27) 8 concurrent writes for 8 projects, each with its own active_document "patches/p<i>.json" → 8 paths, each manifest holds its own active_document (target (8a) for the key; the private staging holds)

verify_written_manifest
req: LLR-169.3
in: Path project_dir; ProjectVariantSet variant_set; Path project_root; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; Optional[str] active_document = None
out: ManifestVerifyResult result
func: changed. `"active_document"` joins the drift domain: compared as text, re-read `manifest.active_document` (Optional[str], group C) against the intended text (`None` equals an absent key). An absent manifest adds "active_document" to its full drift list. A re-read issue still forces MISMATCH (R-1), so a refused key on re-read is a mismatch even when the drift list is empty.
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-23, A3R2-5 restored from baseline-8a) one digest changed between write and verify → status "mismatch", drift holds "files" (holds at dc3b314; the new key never hides a `files` drift)
examples: (TC-B100-23 boundary, LLR-169.3) written with active_document "patches/boost.json", then project.json edited so active_document is "patches/other.json" before verify → status "mismatch", drift holds "active_document" and only that (1 mismatch) (target (8a))
examples: (TC-B100-23) written and verified with active_document "patches/boost.json", unchanged → status "verified", drift `0` items (target (8a))
examples: (TC-B100-23) intended active_document `None`, project.json has no key → status "verified" (target (8a); holds for every pre-8a manifest)
examples: (TC-B100-23 negative control) mutant leaving active_document out of the domain → the boundary arm gives 0 mismatches → RED (target (8a))
examples: (R-1, LLR-169.3) project.json rewritten between write and verify with active_document "firmware.s19" → re-read active_document `None` with 1 reader issue → status "mismatch" (drift holds "active_document" because `None` ≠ "patches/boost.json") (target (8a))
examples: (LLR-003.x absent manifest) project.json deleted before verify → status "mismatch", drift holds "active_variant" and "active_document", written_path `None` (target (8a) for the added name)

project_file_records
req: LLR-169.2, LLR-169.1
in: Path project_dir; Optional[str] active_document = None
out: dict[str, FileRecord] records
func: changed. The top-level scan is unchanged (O-2: data and A2L suffixes, no sub-folder walk, no link followed). When `active_document` is set AND `is_active_document_form(text)` is True, one more record keyed by the text, computed only if `os.lstat(project_dir / home)` is a regular directory and not a reparse point (S3-8: the home component is checked too, so a junctioned `patches` is never followed) and `os.lstat(project_dir / text)` is a regular file and not a reparse point (the same guard as `_top_level_project_files`); absent, a folder, a link or junction on either component, a bad form or an unreadable file → no record and no raise. No listing of the home folder: at most two `lstat` calls (plus one read to hash the file). Keys sorted as today (the document key sorts among the names).
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-22 / TC-B100-28 A-15 arm, LLR-169.2) P with `firmware.s19`, `firmware.mac`, `firmware.a2l`, `prg.srec`, `flows/f1.json`, `reports/r.md`, `patches/boost.json`, `patches/other.json`; active_document "patches/boost.json" → records keys `5`: "firmware.s19", "firmware.mac", "firmware.a2l", "prg.srec", "patches/boost.json"; "patches/other.json" absent (target (8a))
examples: (TC-B100-22 negative control) mutant leaving the active document out → 4 keys → RED (target (8a))
examples: (TC-B100-22) the same P, active_document `None` → the 4 top-level keys, byte-for-byte the records of today (holds)
examples: (LLR-169.2 "a recorded document absent from disk") active_document "patches/gone.json", no such file → 4 keys, 0 raises (target (8a))
examples: (Inc 7 final-file rule) `P/patches/boost.json` is a symlink or junction → no "patches/boost.json" record, 0 raises (target (8a))
examples: (S3-8) `P/patches` is a junction to a folder outside P that holds `boost.json`, active_document "patches/boost.json" → no "patches/boost.json" record, `0` bytes read outside P, 0 raises (target (8a))
examples: (LLR-170.1 form) active_document "../x.json" or "patches/sub/x.json" → no record for it (the serialize refuses the key itself), 0 filesystem calls for it (target (8a))
examples: (TC-B100-22 OQ-7b fixture) `checks/inner.s19` on disk and active_document "patches/boost.json" → "checks/inner.s19" absent (the walk mutant still finds it) (holds)
examples: (LLR-169.1) the record of "patches/boost.json" equals size and hashlib.sha256 of its bytes (target (8a))

check_project_files
req: LLR-169.5, LLR-170.3, HLR-170
in: Path project_dir; Optional[ProjectManifest] manifest
out: list[ProjectFileProblem] problems
func: changed (signature unchanged). The ONLY owner of `missing` for a recorded `active_document` (LLR-169.5). Order: no manifest → `no project.json` (stop); manifest damaged as a whole → stop (unchanged); then, before the `no digests saved` return, `_active_document_missing(project_dir, manifest)` adds at most one `missing`; then `no digests saved` (stop) or the per-record `_disk_problem` loop and `not recorded` (unchanged). A document WITH a `files` record is checked by `_disk_problem` (missing / changed on disk / not readable), so the helper skips it and the document is never reported twice. Sub-folder files are never `not recorded` (top-level scope, unchanged). The document's problem is named by its project-relative POSIX text exactly as recorded, "patches/boost.json" (A3-1, pre-ruling 3): `_disk_problem` takes the name for the key equal to `manifest.active_document` and keeps `path.name` for every other record; the reopen (group A) uses the same text, so `merge_load_problems` keeps one problem per file.
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-25 arm 1, LLR-169.5) project.json with active_document "patches/boost.json" and a files record for it, `P/patches/boost.json` deleted → problems hold exactly `1` "missing" naming "patches/boost.json" (target (8a))
examples: (TC-B100-25 arm 2, LLR-169.5) active_document "patches/boost.json", files holding only the 4 top-level records, the document absent → exactly `1` "missing" naming "patches/boost.json" (target (8a))
examples: (TC-B100-25 mutant) the document skipped → 0 problems on arm 2 → RED; the helper run also for a recorded document → 2 "missing" on arm 1 → RED (target (8a))
examples: (LLR-169.5 + no digests) active_document "patches/boost.json", no files key, the document absent → 2 problems: 1 "missing" naming "patches/boost.json" and 1 "no digests saved" (target (8a); without the reorder the `missing` would be lost by the early return)
examples: (TC-B100-25) active_document "patches/boost.json" recorded, file present and equal → 0 problems (target (8a))
examples: (LLR-169.5) a recorded document whose bytes changed (same size) → 1 "changed on disk" naming "patches/boost.json", 0 "missing" (target (8a) through `_disk_problem`)
examples: (LLR-169.5) `patches/other.json` on disk, not the active document → 0 problems for it (not "not recorded": scope is top-level) (holds)
examples: (TC-B100-25) a clean project, no active_document → 0 problems; a hand-copied `firmware_9.s19` → 1 "not recorded" (holds)
examples: (HLR-170 threshold) a recorded `patches/boost.json` deleted → 1 problem naming "patches/boost.json", 0 raises (target (8a))
examples: (A3-1, TC-B100-30) `P/patches/boost.json` holds `{` and `files` has a record for it → check_project_files gives `1` "changed on disk" naming "patches/boost.json"; with the reopen's `not readable` for the same name, merge_load_problems keeps exactly `1` "not readable" (target (8a))
examples: (A3-1 negative control) a mutation naming the record by `path.name` ("boost.json") → 2 problems for one file after the merge → RED (target (8a))

_active_document_missing
req: LLR-169.5
in: Path project_dir; ProjectManifest manifest
out: Optional[ProjectFileProblem] problem
func: new (may be written inline in check_project_files; the node exists so its examples and mutant have one home). When `manifest.active_document` is set and has no `files` record (no key of `manifest.files` equals `project_dir.resolve() / text` in the reader's resolved form), `os.lstat(project_dir / text)`: FileNotFoundError → one `missing` problem (detail "recorded in project.json, not on disk"); present (any type) or any other OSError → `None` (a present but unreadable document is the reopen's `not readable`, LLR-170.3, owned by the app: its classifier's `link`, `too_large`, `unreadable` or `io_error`; the same `FileNotFoundError` test gives the classifier's `missing`, so one file is never `missing` here and `not readable` there). Never raises.
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-25 arm 2) active_document "patches/boost.json", no record, file absent → problem "missing" naming "patches/boost.json" (target (8a))
examples: (TC-B100-25 arm 1 guard) active_document "patches/boost.json" with a files record → `None` (the record loop owns it) (target (8a))
examples: (LLR-170.1) active_document `None` → `None`, 0 filesystem calls (target (8a))
examples: (LLR-170.3 ownership) `P/patches/boost.json` present but holding "{" → `None` (the app's reopen adds 1 "not readable") (target (8a))

document_in_home
req: LLR-167.6, LLR-170.2
in: Path project_dir; Path source; str home
out: bool in_home
func: new (A3-9). The ONE test for "the file-backed document is already in its home", called only by `classify_active_document` (its class `in_home`), which `plan_project_save` and `gather_project_artifacts` both call (the app does not decide the kind again). True only when ALL hold: `is_active_document_form(f"{home}/{source.name}")` is True (the reader's predicate); the source's parent folder name equals `home` exactly (case-sensitive, the same exact-home rule as the predicate, A3R2-7) and the grandparent equals `project_dir` as an absolute path compared textually, with `os.path.normcase` for the project part only and no `resolve()` (a sub-folder of the home and a different home are False); and the walk: `os.lstat` of `project_dir / home` is a regular directory and not a reparse point and `os.lstat` of the source is a regular file and not a reparse point. Never raises (any OSError → False). Decision for A3R2-7 (of the two options): the exact home component, so the outcome is the same on every platform; on Windows a hand-made `P/Patches/` costs one status line (the document is not recorded), never a wrong record.
module: s19_app/tui/services/project_gather_service.py
examples: (A3-9) `P/patches/changes.json` regular file, home "patches" → in_home `True`
examples: (A3-9) `P/patches/sub/x.json` → `False` (parent differs)
examples: (A3-9) `P/patches/a.json` is a symlink to a file outside P → `False` (reparse point)
examples: (A3-9) `P/patches` is a junction and the source is `P/patches/x.json` → `False` (home is a reparse point)
examples: (A3-9) `P/checks/x.json` with home "patches" → `False`; `P/patches/x.txt` → `False` (form)
examples: (A3-9) a source outside P, e.g. the common library `boost.json` → `False`
examples: (A3-9 negative control) a mutation comparing resolved paths so that the symlink above counts as in home → `True` → RED
examples: (A3R2-7) `P/Patches/x.json` (a hand-made folder spelled with a capital P), home "patches" → `False` on Windows and on POSIX (the home component is compared exactly)

classify_active_document
req: LLR-167.6, LLR-170.2, HLR-170
in: Path project_dir; Path source; str home
out: tuple(str kind, Optional[str] name)
func: new (E3 R11, A3R2-1, A3R2-6, S3R2-5). The ONE gather classifier of a file-backed active document, called by `plan_project_save`, by `gather_project_artifacts` and by the app's `_plan_project_save` before it digests the source (one function, so the plan and the written tree agree). `project_dir` and `source` are the unresolved paths the app passes. Order: (1) `os.lstat(source)`: `FileNotFoundError`, any other `OSError`, not a regular file, or a link or reparse point → `missing` (the source cannot be used; a link is never followed or copied, the Inc 7 final-file rule applied to the source, S3R2-5). (2) "inside the project" is decided on the UNRESOLVED text: `os.path.normcase(os.path.abspath(source))` starts with `os.path.normcase(os.path.abspath(project_dir)) + os.sep` (`..` collapsed textually, no `resolve()`, so a link cannot move a source in or out). Inside and `document_in_home(project_dir, source, home)` True → `in_home`; inside and False → `inside_elsewhere` (top level, another home, a sub-folder of the home, a home spelled with another case). (3) Otherwise → `outside`. `name` is the file name the gather places (the source's own name: the final component is a regular file, so the placement's `resolved_source.name` is the same, A3R2-6) for `in_home` and `outside`, `None` for the other two. Rows and actions: `in_home` → 1 row, `keep`; `outside` → 1 row, the predicted `new` or `keep`, copied; `inside_elsewhere` and `missing` → 0 document rows, nothing copied, one status line (app), the document counts as not placed (R3). The save is never refused because of the document's class, digest or absence. Never raises.
module: s19_app/tui/services/project_gather_service.py
examples: (E3 R11) `P/patches/changes.json` regular, home "patches" → kind "in_home", name "changes.json"
examples: (E3 R11) `boost.json` in the common library, outside `P` → kind "outside", name "boost.json"
examples: (E3 R11, A3R2-1) `P/notes/x.json`, `P/x.json`, `P/patches/sub/x.json` and, for home "patches", `P/checks/x.json` → kind "inside_elsewhere", name `None`
examples: (E3 R11, A3R2-1) a source deleted after its load → kind "missing", name `None`, `0` raises
examples: (E3 R11, S3R2-5) `P/patches/a.json` is a symbolic link to `C:/Users/u/notes/private.json` → kind "missing", name `None`, `0` bytes read through the link
examples: (E3 R11, S3R2-5) an outside source that is a symbolic link → kind "missing", name `None`
examples: (E3 R11, S3R2-5) `P/patches` is a junction to a folder outside `P` and the source is `P/patches/x.json` → kind "inside_elsewhere" (inside on the unresolved text; `document_in_home` False), never "outside"
examples: (E3 R11 negative control, S3R2-5) a mutation deciding "inside" on the resolved path → the junction source above is "outside" and copied → RED

gather_project_artifacts
req: LLR-170.2, LLR-138.1, LLR-138.2, LLR-164.2
in: Path project_dir; Sequence[str] composition_names = (); Optional[Path] active_document = None; str active_document_kind = "change"; Optional[Path] active_template = None; Path common_patches_dir; Path common_templates_dir; Path workarea_root
out: GatherOutcome outcome
func: changed (signature unchanged; the outcome gains `active_document`, now project-relative text). Limb 2a starts with `classify_active_document(project_dir, document, home)` on the UNRESOLVED paths (E3 R11, the same call the planner makes), before any `resolve()` (S3R2-5: today's limb resolves first, `project_gather_service.py:497-505`). (a) `outside` → copied into `document_home_for_kind(kind)` as today; the source is a regular file, not a link (the classifier `lstat`-ed it), so the placement's name is the predicted name (A3R2-6); the outcome names the landing. (b) `in_home` (the file sits directly in its kind's home, the home and the file are regular and not reparse points per `os.lstat`) → no copy, no `written` entry, no `gathered` row (unchanged rule), the outcome names it (closes C3); this is also the case of a document the app wrote or bound earlier. (c) `inside_elsewhere` (inside the project on the unresolved text, anywhere else: top level, another home, a sub-folder of the home, a home with another case) → no copy, `active_document` `None`, one GATHER finding naming it (no new bytes). (d) `missing` (absent, not a regular file, or a link or reparse point) → no copy, `active_document` `None`, one GATHER finding (`GATHER-SOURCE-MISSING` for an absent source, as today; a link finding for a link). In every case the landing text is `f"{home}/{landing.name}"` built from the home constant and the placement's file name (A3-12), never from a resolved path; it is named only if `is_active_document_form` of that text is True; otherwise the copy (if any) stays as today, `active_document` `None` and one finding. A refused copy → `None` with the existing finding. The gather never refuses the save because of the document; the app paints the one status line for (c) and (d). The gather never writes the editor's pasted document: the app writes it (LLR-170.2) and passes the landing; that landing is case (b), so the gather adds nothing to `written` and the app's own placed-files list owns its rollback. The ≥1-entry rule is the app's and applies only to a pasted document (pre-ruling 8).
module: s19_app/tui/services/project_gather_service.py
modify: [I/O: project folder] (append)
examples: (TC-B100-29, LLR-170.2) the app wrote `P/patches/changes.json` (1 entry) and passes it, kind "change" → outcome.active_document == "patches/changes.json" (project-relative text), written `0` items, gathered has no "patches" row from it, 0 bytes written by the gather (target (8a))
examples: (TC-B100-29 check home) the app wrote `P/checks/changes.json`, kind "check" → outcome.active_document == "checks/changes.json" (target (8a))
examples: (TC-B100-29 `_1`) the app's write landed `P/patches/changes_1.json` beside a different `changes.json` → outcome.active_document == "patches/changes_1.json" (target (8a))
examples: (TC-B100-29 file-backed, test_tc700_active_editor_document_is_gathered_by_kind) `boost.json` kind "change" in the common library → 1 file `P/patches/boost.json` byte-equal to the source, written holds it, gathered "patches" holds "patches/boost.json", outcome.active_document == "patches/boost.json" (target (8a) for the naming; the copy holds)
examples: (LLR-163.1 reuse) a byte-identical `P/patches/boost.json` already exists and the source is outside P → written `0` items, gathered "patches" holds "patches/boost.json", active_document == "patches/boost.json" (target (8a) for the naming)
examples: (M-1 clash) a different `P/patches/boost.json` exists, source outside P → landing `P/patches/boost_1.json`, active_document == "patches/boost_1.json" (target (8a))
examples: (E3 R1, second Save project) the document already bound to `P/patches/changes.json` (a file-backed document in its home) → case (b): active_document == "patches/changes.json", 0 files copied, 0 bytes written (target (8a))
examples: (A3-12, A3R2-7) a hand-made folder `P/Patches/` (capital P) holding `x.json`, kind "change" → class "inside_elsewhere" on Windows and on POSIX (the home component is compared exactly), active_document `None`, issues `1`, 0 bytes written; the text is never built from the on-disk case, so active_document is never "Patches/x.json" (target (8a))
examples: (case (c), E3 R11) active document `P/notes/x.json` or `P/x.json` or `P/patches/sub/x.json` → active_document `None`, issues `1`, 0 bytes written (target (8a); today: skipped with no finding)
examples: (case (c), wrong home) kind "change" and `P/checks/x.json` → active_document `None`, issues `1` (target (8a))
examples: (form guard) an outside source named `boost.txt` → copied to `P/patches/boost.txt` as today, active_document `None`, issues `1` (target (8a); otherwise the serialize would refuse the whole manifest)
examples: (Inc 7 final-file rule, E3 R11, S3R2-5, A3R2-6) `P/patches/a.json` is a symlink to `C:/Users/u/notes/private.json` → class "missing" (`os.lstat` reparse), `0` bytes copied, active_document `None`, issues `1` (a GATHER finding), never "patches/a.json" or "patches/private.json" (target (8a))
examples: (E3 R11, S3R2-5, save into another project) the bound source `P/patches/boost.json` was replaced by a symlink during the session, Save project into `Q` → class "missing", `0` bytes copied into `Q`, active_document `None`, issues `1` (target (8a))
examples: (E3 R11 negative control, S3R2-5) a mutation resolving the source before the class decision → the link target's bytes are copied into `P/patches/` → RED (target (8a))
examples: (SEC-1 / R3-3) `P/patches` is a junction to a folder outside P and the source is outside → the copy is refused (GATHER-CONTAINMENT), active_document `None`, 0 bytes written outside the work area (holds for the refusal; target (8a) for `None`)
examples: (existing, E3 R11) a deleted outside source → class "missing", issues holds "GATHER-SOURCE-MISSING", active_document `None`, the gather returns normally (holds; target (8a) for `None`)
examples: (QC-3) no active document, no composition → gathered empty, issues `0`, active_document `None` (holds)

plan_project_save
req: LLR-167.6, LLR-170.2, LLR-164.2
in: Path target; str target_kind; Sequence[PlannedFile] files; str image; Sequence[str] manifest_keys; Optional[str] refusal = None
out: SavePlan plan
func: changed (signature unchanged; PlannedFile gains `home`, see entities). Each PlannedFile is predicted under `target / planned.home` (the home is None for the image, MAC and A2L rows: unchanged). For a row of role "document" with a `source` (file-backed): `classify_active_document(target, source, home)` (the one gather classifier, E3 R11, the same call the gather makes). `in_home` (a file-backed document already in its home, including one bound by an earlier Save project) → landing = that file, action `keep` (recorded as it is on disk, never written; `replace` is withdrawn, E3 R1). `outside` → `predict_placement(digest, size, target / home, name)` with the name the classifier returns (the name the gather places, A3R2-6): reused → `keep`, else `new` (the `_<N>` name comes from the prediction). `inside_elsewhere` or `missing` → 0 document rows (the gather copies nothing and names nothing for them, so the plan equals the written tree, A3R2-1; the app normally builds no `PlannedFile` for them, and the planner applies the same rule if one is passed). A pasted document (`source` None) skips the classifier and is always predicted (`new` or `keep`). The `project.json` row: `merge` when target_kind is "merge", else `rewrite` / `new` as today. A refusal → no rows (unchanged). Still pure: 0 bytes written, the payload digest is an input; the only reads are the target listing, the classifier's `lstat` calls and the candidate files that `predict_placement` compares (as today).
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59 Inc 8a arm, LLR-167.6) fresh `P1`, files [image `firmware.s19`, document "changes.json" home "patches" source a pasted document] → rows: image "new", document landing ends "patches/changes.json" action "new", manifest "new" (target (8a))
examples: (TC-B100-59) a different `P/patches/changes.json` exists, a pasted document → document landing ends "patches/changes_1.json" action "new" (target (8a))
examples: (TC-B100-59) an identical `P/patches/changes.json` exists, a pasted document → document landing ends "patches/changes.json" action "keep" (target (8a))
examples: (TC-B100-59, E3 R1) the document bound to `P/patches/changes.json` and edited (the source file's digest equals the file's) → landing ends "patches/changes.json" action "keep", `0` rows with action "replace" (target (8a))
examples: (TC-B100-59, E3 R1) bound and unchanged → "patches/changes.json" action "keep" (target (8a))
examples: (E3 R1 edge) bound to `P/patches/changes.json` while `P/patches/changes_1.json` holds other bytes → landing "patches/changes.json" action "keep"; the sibling is not touched (target (8a))
examples: (TC-B100-59) a file-backed document `boost.json` from outside P → 1 document row landing ends "patches/boost.json" action "new" (target (8a))
examples: (TC-B100-59) no document → 0 rows of role "document" (target (8a))
examples: (TC-B100-59 merge, LLR-164.2) target_kind "merge", `ab/project.json` exists → plan.target_kind "merge", the "project.json" row action "merge" (not "rewrite") (target (8a))
examples: (LLR-164.2 merge with a session document) target `ab` whose `patches/changes.json` is its own active document, a pasted session document with other bytes → document row "patches/changes_1.json" "new"; no row touches `ab/patches/changes.json` (target (8a))
examples: (LLR-164.2 merge, E3 R1, S3-5) target `ab`, the session document is file-backed `ab/patches/notes.json`, edited → document row "patches/notes.json" action "keep", `0` rows with action "replace"; `ab/patches/notes.json` 0 bytes changed (target (8a))
examples: (A3-9, E3 R11, A3R2-1) a document loaded from `P/patches/sub/x.json` → class "inside_elsewhere", `0` document rows, never `keep` or `new`; matches the gather's case (c) (0 bytes written) (target (8a))
examples: (E3 R11, A3R2-1) a document loaded from `P/notes/x.json` or `P/x.json` → `0` document rows (target (8a))
examples: (E3 R11, A3R2-1) a file-backed `boost.json` from outside P, deleted before the plan → class "missing", `0` document rows, `0` raises (target (8a))
examples: (E3 R11, A3R2-6) `P/patches/a.json` is a symbolic link to `outside/real.json` → class "missing", `0` document rows (never a `patches/a_1.json` row that the gather would write as `patches/real.json`) (target (8a))
examples: (TC-B100-59 negative control, A3R2-1) a mutation without the `inside_elsewhere` class → `1` document row with no file in the written tree → RED (target (8a))
examples: (TC-B100-59 mutant) always "new" for the document → 1 action-word difference on the `keep` arm (bound or identical) → RED (target (8a))
examples: (TC-B100-59) manifest_keys passed holding "active_document" → plan.manifest_keys holds "active_document"; passed without → not held (holds: the keys are an input, LED .45)
examples: (TC-B100-59 refused) refusal "blocked" with a document file → rows `0`, 0 bytes written (holds)
examples: (TC-B100-59) target `P1` new, files [image `firmware.s19`] → rows image "new", manifest "new" (holds)

## Entities

[Data: GatherOutcome.active_document]
in: Optional[str]
desc: new field (interfaces-8a.md, pre-ruling 3). The project-relative POSIX text of the landed document, `f"{home}/{landing.name}"` built from the home constant (A3-12), e.g. "patches/changes.json" (written this save by the app and passed in, copied this save by the gather, or already in its kind's home); `None` when there is no document, it was not placed, or its landing fails is_active_document_form. Default `None`, so every existing constructor call keeps working. The app records it as `active_document` as it is.

[Data: PlannedFile.home]
in: Optional[str]
desc: new field, default None (top level), so the three existing image / MAC / A2L constructions are unchanged. "patches" or "checks" for the role "document" row. Its value comes from document_home_for_kind of the document's kind (app side).

[Data: PlannedFile.source]
in: Optional[Path]
desc: changed type (pre-ruling 5, A3R2-5; today `source: Path`, project_gather_service.py:726): `None` for a pasted document; the planner skips `classify_active_document` when it is `None`. For a file-backed document it is the unresolved source path the app holds.

[Data: PlannedFile.role]
in: str
desc: changed value set (A3R2-5; docstring at project_gather_service.py:717): adds "document" beside the image, MAC and A2L roles; the planner turns it into a `SavePlanRow` of role "document".

[Data: SavePlanRow.role]
in: str
desc: changed value set: adds "document" (new constant PLAN_ROLE_DOCUMENT). The row's landing is the full path under the home, so the plan-equals-written-tree check compares it by full path (LLR-167.6 "by full path and action"). The document row's action is `new` or `keep` only.

[Data: plan action words]
in: str
desc: new constant PLAN_ACTION_MERGE = "merge" (the module comment at project_gather_service.py:690-692 says Inc 8a adds it). No `replace` constant is added and none is produced in 8a (E3 R1): a document is never overwritten. The module comment changes to "`merge` is added at 8a; `replace` is not produced at 8a" (A3R2-5).

## Findings

finding P-B1 a document landing outside the form would refuse the whole manifest
anchor: gather_project_artifacts
seen: (design read, no run) an outside document named `boost.txt` (or `boost.JSON`, or an overlong name) is copied today to `patches/boost.txt`; if the app records it, serialize_manifest refuses every key and the save rolls back
cause: the gather accepts any file name; only the writer applies the form predicate
decision: the gather names a landing only when is_active_document_form holds (examples above); the landing text is built from the home constant (A3-12); confirmed by pre-ruling 2

finding P-B2 `missing` for a document without `files` would be lost when the manifest has no `files` key
anchor: check_project_files
seen: (design read of manifest_writer.py:1096-1098) the `no digests saved` branch returns before any per-file check
cause: early return
decision: the document check runs before that return (examples above)

finding P-B3 the writer accepts a sub-folder `files` key that the reader refuses
anchor: serialize_manifest
seen: (design read) the `files` loop checks keys with `_reject_unsafe_entry` (manifest-keys mode) only; `patches/other.json` passes there, while LLR-169.4 makes the reader refuse it unless it equals active_document
cause: the scope rule lives only in the reader
decision: adopted (pre-ruling 4, P-3): the writer refuses a sub-folder `files` key unless it equals `active_document`; example added to serialize_manifest

### Design risks (section 2) — each block below is a note for people; the parser skips `###` blocks
Seams with group A (`app.py`) and group C (`variant_execution_service.py`), then Inc 7 rules at risk. "A:" / "C:" says who must act.

### R-1 (C) import cycle in the one predicate
interfaces-8a.md defines `is_active_document_form` by "`document_home_for_kind` values", which live in `project_gather_service.py`; that module already imports from `variant_execution_service.py` (line 79). Importing back gives a cycle.
Mitigation: the predicate uses its own `("patches", "checks")` constant in `variant_execution_service.py`, and one test pins it equal to `{document_home_for_kind("change"), document_home_for_kind("check")}`. See P-2.

### R-2 (C) case rule of the predicate is not defined
`Patches/x.json`, `patches/X.JSON`: RESOLVED by pre-ruling 1: the home component is exact lowercase (the app writes lowercase), the `.json` suffix is compared case-insensitively, and control characters are refused (E3 R6). So `patches/boost.JSON` is accepted at both ends and `Patches/x.json` is refused at both ends. The gather's form guard (P-B1) and the writer use C's predicate, so the rule holds at both ends.

### R-3 (C) a refused `active_document` and SEC6-2
If the reader refuses `active_document` (1 issue, `None`), `manifest_rewrite_refusal` counts it as a skipped entry: the four carry writers refuse the rewrite (correct: they cannot carry it) and Save project keeps `project.json.previous-<UTC>` (SEC7-3), with the status naming the copy and the dropped value (E3 R5). Group C makes it so.

### R-4 (C) the `files` key of the document needs the accepted text
The reader accepts the `files` key equal to the accepted `active_document` (LLR-169.4). project_file_records keys the record by the exact text the app passes, so the app must pass the same text it writes as `active_document` (one variable, A). If the reader resolves both and compares Paths, a `files` key and `active_document` that differ only in case are accepted on Windows and refused on POSIX (R2-3 shape). C: compare the texts.

### R-5 (A) two computations of one landing
The plan's document row (predict_placement, before any write) and the real landing (write_change_document, or the gather's copy) are two computations. LLR-167.6 requires 0 differences; the existing handler already reports a prediction/placement mismatch naming both paths (B100-I17) for the image rows. A applies the same check to the document row, and passes the document's digest and size computed from `serialize_change_document` bytes (pasted) or from the file bytes (file-backed, never written by the app).

### R-6 (A) LED .72 Q1 versus LLR-167.8 and LLR-170.2 — RESOLVED by E3 R1
The in-place rewrite and the `replace` action are withdrawn. A pasted document is written as a new file and then bound (Q1); a bound document, like any file-backed document already in its home, is recorded as `keep` and never rewritten, so the `replace` row and LLR-167.8's file-backed arm no longer contradict. The merge case is clear too: a session document from the target's home is `keep`, 0 bytes changed.

### R-7 (A) rollback must not remove a reused document — kept
When write_change_document reuses an identical `changes.json` (M-1), the app did not create it. If the app adds it to the save's placed files anyway, a later failure deletes a user file (the SEC2-7 shape). The gather never adds an in-home document to `written` (case (b)); A must add the document to placed files only when its write created it.

### R-8 (A) relative text from the absolute landing — RESOLVED by P-1
The outcome now holds project-relative text built from the home constant (A3-12), so no `relative_to` on a resolved folder is needed.

### R-9 (A) merge carry and a missing target document — amended by E3 R2 and R8 refined
In a merge or an open-project save with no session document, the carried target `active_document` is written as it is unless Save project (group A) drops it: the app's one classifier (`recorded_document_state`, E3 R10) says `missing`, `link` or `unreadable` → dropped with one status line; `ok`, `too_large` or `io_error` → kept (E3 R2, R8 refined). The writer itself still does not check existence or readability, and a mutation passing the session `None` stays LLR-164.2's negative control.

### R-10 (A) one problem per document on Load — RESOLVED by A3-1
check_project_files names the document by its project-relative text "patches/boost.json" (the `_disk_problem` for the key equal to `manifest.active_document` and `_active_document_missing` both use it), and the reopen (A) names it the same way, so LLR-169.9's one-problem-per-file merge keys on one string. A `{` file with a `files` record gives `changed on disk` and `not readable` for the same name, merged into 1 `not readable`.

### R-11 (Inc 7) rules checked against the new key
Private staging (LLR-169.7): unchanged — a refusal returns before the stage directory exists (write_project_manifest example). SEC7-2 re-check after the replace: unchanged. SEC6-2 refuse-rewrite: depends on R-3 (C). Carry: the key is carried as recorded by the four carry writers; Save project drops it only on `missing`, `link` or `unreadable`, with a status line, and keeps it on `too_large` and `io_error` (R-9, E3 R2, R8 refined). `files` scope (O-2): one extra record by exact text, no sub-folder listing; `checks/inner.s19` still not recorded. Walk and folder ceiling (SEC7-1, R2-2): the document goes through the serialize's one walk; it adds at most 2 folder checks. CI-6-1 length rule: the predicate decides on the text first. Final-file link rule: refused at the writer, not recorded by project_file_records, not named by the gather, and a link source is never copied (class `missing`, E3 R11, S3R2-5). Byte identity of manifests without the key (TC-B100-21): kept by emitting the key last and only when set.

### Proposed changes to interfaces-8a.md (section 3) — status after E3 round 1
P-1. ACCEPTED (pre-ruling 3): `GatherOutcome.active_document: Optional[str]` — the project-relative POSIX text, built by the gather from the home constant and the placement's file name, `f"{home}/{landing.name}"` (A3-12), not from a resolved path — in place of an absolute `Optional[Path]`. Reason: one representation end to end (`ProjectManifest.active_document`, `serialize_manifest`, `verify_written_manifest` and `project_file_records` all take the text), and R-8 disappears.
P-2. `is_active_document_form` takes its two homes from a constant in `variant_execution_service.py`, not from `document_home_for_kind` (R-1), with a test pinning equality.
P-3. ACCEPTED (pre-ruling 4): `serialize_manifest` refuses a `files` key with more than one component unless it equals `active_document` — the LLR-169.4 scope at the writer, so the writer cannot write what the reader refuses (P-B3).
P-4. `PlannedFile.home: Optional[str] = None` and the role value "document" (plus PLAN_ACTION_MERGE) are additions on the gather side (pre-ruling 5); A builds the document PlannedFile with them. `PLAN_ACTION_REPLACE` is not produced by the document row in 8a (E3 R1).
