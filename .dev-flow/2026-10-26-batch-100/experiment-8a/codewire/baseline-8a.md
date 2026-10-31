# Code-Wire baseline — batch-100 Inc 8a slice at main `dc3b314`

Scope: the functions on the Inc 8a paths (US-160, M-2, D4) that read or write the change document, `active_document`, `gathered`, or carry manifest keys: Save project (plan → gather → write → manifest), the manifest writer and reader, the in-project rewrite carry, Load project and the document reopen seam, and the Patch Editor panel's `mark_saved`.

Example lines are taken from `01-requirements.md` (the TC/AT/LLR numeric pass thresholds) or from an existing test id; each names its source. A line marked "target (8a)" states what the requirement asks for and does not hold at `dc3b314`; a line marked "holds at dc3b314" is behaviour the requirement keeps. `func:` says "8a changes: …" where an Inc 8a LLR changes the function.

## Nodes

_save_manifest_keys
req: LLR-167.6, LLR-170.1
in: Sequence[DeclaredRegion] declared_regions; bool derived = False
out: tuple[str, ...] keys
func: the project.json keys a Save project writes, read off serialize_manifest, passed to the save plan as an input. 8a changes: an active document adds `active_document` to the keys (today the function has no document input, so the plan can never list it).
module: s19_app/tui/app.py
examples: (TC-B100-59, test_tc_b100_59_plan_keys_equal_written_keys_with_derived_from) declared_regions () and derived `True` → keys hold "files" and "derived_from" (holds at dc3b314)
examples: (TC-B100-59, LLR-167.6 "the app passes the keys it writes") a save whose Patch Editor holds `patches/boost.json` with 1 entry → keys hold "active_document" (target (8a))

S19TuiApp._plan_project_save
req: LLR-167.6, LLR-170.2
in: Path project_dir; str project_name; _ProjectImageStep image_step; bool derived = False
out: SavePlan plan
func: builds the PlannedFile list (image, MAC, A2L) with digests and the target kind (new, open project, merge), then calls plan_project_save. 8a changes: the document row (the active change or check document, or the pasted document as `patches/changes.json`) and its landing name.
module: s19_app/tui/app.py
examples: (TC-B100-59, test_tc_b100_59_fresh_folder) fresh folder `P1`, image `firmware.s19` unchanged → plan.rows image action "new", plan.target_kind "new" (holds at dc3b314)
examples: (TC-B100-59 Inc 8a arm, LLR-170.2) a pasted document with 1 entry → plan has one row landing `patches/changes.json` with action "new"; a different `changes.json` already in `P/patches/` → landing `patches/changes_1.json` (target (8a))

plan_project_save
req: LLR-167.6
in: Path target; str target_kind; Sequence[PlannedFile] files; str image; Sequence[str] manifest_keys; Optional[str] refusal = None
out: SavePlan plan
func: pure planner: one row per top-level file with its predicted landing name and action word, plus the project.json row; writes nothing and hashes nothing. 8a changes: a row for the document (LLR-167.6 "the document"); SavePlan has no document field at dc3b314.
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59, test_tc_b100_59_fresh_folder) target `P1` new, files [image `firmware.s19`] → rows image "new" and manifest `project.json` "new" (holds at dc3b314)
examples: (TC-B100-59 Inc 8a arm) files [image `firmware.s19`, document `patches/boost.json`] into a merge target → a row for `patches/boost.json` and the manifest row "rewrite" (target (8a))

S19TuiApp._handle_save_dialog
req: HLR-170, LLR-170.2, LLR-167.8, LLR-164.2, LLR-167.6
in: Optional[SaveProjectPayload] payload
out: None
func: Save project: name guards, plan, folder, placements, gather, manifest write through the seam, commit block (adopt the re-derived image, ChangeService.mark_saved, status). 8a changes: (a) write a document with no source_path through write_change_document into `<project>/patches/` (LLR-170.2); (b) pass the landed document as `active_document` to _write_and_verify_manifest; (c) in a merge, carry the target's `gathered` and `active_document` (LLR-164.2; the code comment at app.py:9207 says "the full merge carry arrives at Inc 8a"); (d) call PatchEditorPanel.mark_saved after the document is written (LLR-167.8; the commit block at dc3b314 calls only ChangeService.mark_saved).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._change_service] (replace); [I/O: project folder] (append)
examples: (AT-B100-08, HLR-170) one entry pasted at `0x8000007C`, Save project `P` → `P/patches/changes.json` holds 1 entry and `P/project.json` has active_document "patches/changes.json" (target (8a); P-8: nothing under `patches/` at 1d677ba)
examples: (TC-B100-05 Inc 8a arm, LLR-164.2) exact name `ab` of a project that is not open, whose project.json holds gathered and active_document "patches/boost.json" → after the merge both keys equal (0 changed) (target (8a))
examples: (TC-B100-70, test_tc_b100_70_refused_save_keeps_the_flag) a blocked document → status holds "blocked" and the panel flag stays `True` (holds at dc3b314)
examples: (TC-B100-70 positive arm, LLR-167.8) an entry added → Save project wrote the document → panel flag `False`, then a project load asks 0 questions (target (8a); test_tc_b100_70_unwritten_document_keeps_the_flag asserts the flag stays `True` for this case today and must be re-pinned)

gather_project_artifacts
req: LLR-170.2, LLR-138.1
in: Path project_dir; Sequence[str] composition_names = (); Optional[Path] active_document = None; str active_document_kind = "change"; Optional[Path] active_template = None; Path common_patches_dir; Path common_templates_dir; Path workarea_root
out: GatherOutcome outcome
func: copies the documents the project uses into `patches/` or `checks/` by kind (and the CRC template into `templates/`); returns the `gathered` rows, the files it wrote and the homes it created. A document already inside the project is skipped and gets no row. 8a changes: the outcome names the landed project-relative path of the active document (LLR-170.2 "whose GatherOutcome names the landed project-relative path").
module: s19_app/tui/services/project_gather_service.py
modify: [I/O: project folder] (append)
examples: (test_project_gather.py::test_tc700_active_editor_document_is_gathered_by_kind) active_document `boost.json` of kind "change" in the common library → outcome.gathered "patches" holds "patches/boost.json" (holds at dc3b314)
examples: (TC-B100-29, LLR-170.2) a file-backed document → 1 file in `P/patches/`, byte-equal to the source, and the outcome names its project-relative path (target (8a) for the naming; a document already in `P/patches/` gets no row today)

write_change_document
req: LLR-170.2
in: ChangeDocument document; Path base_dir; str file_name = DEFAULT_CHANGE_FILE_NAME; Optional[CopyIntoWorkarea] copy_fn = None; Optional[Path] dest_dir = None
out: tuple[Optional[Path], list[ValidationIssue]] result
func: serializes a change document and places it through copy_into_workarea (M-1 rule: a byte-identical file is reused, a clash lands as `_<N>`); `dest_dir` selects the project home. No Save project caller at dc3b314; 8a adds _handle_save_dialog as a caller.
module: s19_app/tui/changes/io.py
examples: (TC-B100-29, LLR-170.2) a pasted document with 1 entry, dest_dir `P/patches` → path ends "changes.json", issues `0`; a different `changes.json` there → path ends "changes_1.json" (target (8a) as a Save project path)

S19TuiApp._write_and_verify_manifest
req: LLR-169.2, LLR-170.1, LLR-168.3
in: Path project_dir; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; Optional[Callable[[Path], None]] on_written = None
out: bool ok
func: the manifest seam: computes `files` from disk (project_file_records), writes project.json through write_project_manifest, verifies it, surfaces the result. 8a changes: an `active_document` input threaded into the write and the verify, and the active document added to `files` (LLR-169.2 active-document arm).
module: s19_app/tui/app.py
modify: [I/O: project.json] (replace); [Data: S19TuiApp._last_manifest_verify_result] (replace)
examples: (TC-B100-22, test_tc_b100_22_seam_scope_is_top_level_data_and_a2l) a project with `firmware.s19`, `firmware.mac`, `firmware.a2l`, `prg.srec`, `flows/f1.json`, `reports/r.md` → files keys are the 4 top-level files, ok `True` (holds at dc3b314)
examples: (TC-B100-28 A-15 arm, LLR-169.2) the same project with active document `patches/boost.json` → files holds "patches/boost.json" beside the 4 top-level files (target (8a); LLR-170.1's threshold says "4 keys" — see baseline-notes)

serialize_manifest
req: LLR-170.1, LLR-169.1, LLR-168.4
in: ProjectVariantSet variant_set; Path project_root; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; int schema_version = DEFAULT_SCHEMA_VERSION
out: tuple[Optional[str], list[ValidationIssue]] result
func: the canonical project.json text; optional keys are written only when non-empty, each path through _reject_unsafe_entry. 8a changes: an `active_document` input, emitted as a project-relative POSIX path under `patches/` or `checks/`, only when set.
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-21, test_manifest_writer.py pins) no files, no derived_from → text byte-identical to the `1d677ba` output (holds at dc3b314)
examples: (TC-B100-28) active_document "patches/boost.json" → text holds "patches/boost.json" and reads back equal (target (8a))

write_project_manifest
req: LLR-169.7, LLR-170.1
in: ProjectVariantSet variant_set; Path project_root; Path base_dir; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; int schema_version = DEFAULT_SCHEMA_VERSION
out: tuple[Optional[Path], list[ValidationIssue]] result
func: serializes and writes project.json through a private staging directory and os.replace. 8a changes: threads `active_document` to serialize_manifest.
module: s19_app/tui/services/manifest_writer.py
modify: [I/O: project.json] (replace)
examples: (TC-B100-27) 8 concurrent writes for 8 projects → 8 paths returned, each manifest holds its own active_variant (holds at dc3b314)
examples: (TC-B100-28) active_document "patches/boost.json" → the written file holds "patches/boost.json" (target (8a))

verify_written_manifest
req: LLR-169.3
in: Path project_dir; ProjectVariantSet variant_set; Path project_root; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None
out: ManifestVerifyResult result
func: re-reads project.json and compares active_variant, batch, assignments, files and derived_from with the intent. 8a changes: `active_document` joins the drift domain (LLR-169.3 names it; the "changed active_document only" boundary arm is the 8a part).
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-23) one digest changed between write and verify → status "mismatch", drift holds "files" (holds at dc3b314)
examples: (TC-B100-23 boundary, LLR-169.3) only active_document changed between write and verify → status "mismatch", drift holds "active_document" (target (8a))

project_file_records
req: LLR-169.2
in: Path project_dir
out: dict[str, FileRecord] records
func: one size + SHA-256 record per top-level data or A2L file, from disk; walks no sub-folder. 8a changes: the active document under `patches/` or `checks/` must be recorded too (LLR-169.2 "and the active document"); today it cannot be, because the scan is top-level only and has no document input.
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-22) `firmware.s19`, `firmware.mac`, `firmware.a2l`, `prg.srec`, `flows/f1.json`, `reports/r.md` → records keys "firmware.s19", "firmware.mac", "firmware.a2l", "prg.srec" (holds at dc3b314)

PatchEditorPanel.mark_saved
req: LLR-167.8, LLR-005.1
in:
out: None
func: clears the panel's dirty flag and repaints the indicator. No change; 8a adds _handle_save_dialog as a caller.
module: s19_app/tui/screens_directionb.py
modify: [Data: PatchEditorPanel._dirty] (replace)
examples: (TC-B94-10 save-then-check arm, cited in the docstring) a clean save_doc → [Data: PatchEditorPanel._dirty] `False` (holds at dc3b314)

read_project_manifest
req: LLR-170.1, LLR-168.1, LLR-169.4
in: Path project_dir; Optional[SizeProbe] size_probe = None
out: Optional[ProjectManifest] manifest
func: the capped, collect-don't-abort reader of project.json. Keys outside KNOWN_MANIFEST_KEYS go to `unknown_keys`; `files` keys must be top-level data or A2L names. 8a changes: parse `active_document` (prefix `patches/` or `checks/`, suffix `.json`, else one issue and `None`), add it to KNOWN_MANIFEST_KEYS, and accept the active document's path as a `files` key (LLR-169.4 "and not active_document").
module: s19_app/tui/services/variant_execution_service.py
examples: (TC-B100-18, test_tc_b100_18_valid_gathered_is_an_equal_dict) gathered {"patches": ["patches/boost.json"]} → manifest.gathered equal dict, 0 issues (holds at dc3b314)
examples: (TC-B100-28) active_document "patches/boost.json" → manifest.active_document round-trips; "../x.json", an absolute path, `7`, "firmware.s19", "project.json" → 5 issues, active_document `None` each; absent → `None`, 0 issues (target (8a); at dc3b314 the key lands in unknown_keys "active_document")

manifest_keep_reason
req: LLR-168.3, SEC7-3
in: ProjectManifest manifest
out: Optional[str] reason
func: why Save project must keep a copy of the previous project.json before rebuilding it: damaged, another schema_version, or unknown keys. No code change in 8a; its result changes once `active_document` is a known key.
module: s19_app/tui/services/variant_execution_service.py
examples: (TC-B100-05 Inc 8a merge arm) a target project.json holding active_document "patches/boost.json" → reason `None`, no kept copy (target (8a); at dc3b314 → "holds keys this version does not know")

manifest_rewrite_refusal
req: LLR-168.3
in: ProjectManifest manifest
out: Optional[str] reason
func: why an in-project writer must not rewrite project.json (keep reason, or skipped entries). No code change in 8a; its result decides whether the four carry writers rewrite a manifest that holds `active_document`.
module: s19_app/tui/services/variant_execution_service.py
examples: (TC-B100-20, test_tc_b100_20_rewrite_never_drops_what_it_cannot_carry) a manifest with an unknown top-level key → reason "holds keys this version does not know" (holds at dc3b314)
examples: (AT-B100-20, LLR-168.3) a manifest with batch, assignments, declared_regions, gathered and active_document all set → reason `None` (target (8a))

check_project_files
req: LLR-169.5, HLR-170
in: Path project_dir; Optional[ProjectManifest] manifest
out: list[ProjectFileProblem] problems
func: the Load-side check of manifest and disk problems; never raises. 8a: the active document's `files` record is checked like the others ("changed on disk", "missing"); whether a missing recorded document is listed here or by _handle_load_project (LLR-170.3) is open (see baseline-notes).
module: s19_app/tui/services/manifest_writer.py
examples: (TC-B100-25) a clean project → 0 problems; a hand-copied `firmware_9.s19` absent from `files` → 1 problem "not recorded" (holds at dc3b314)
examples: (HLR-170 threshold) a recorded `patches/boost.json` deleted → 1 problem naming "boost.json", the project opens (target (8a))

S19TuiApp._manifest_carry
req: LLR-168.3, LLR-164.2
in: Path project_dir; Optional[ProjectManifest] manifest
out: dict carry
func: the keys an in-project writer does not own, read back from disk and made project-relative: batch, assignments, declared_regions, gathered, derived_from. 8a changes: carry `active_document` (and the Save project merge uses the full carry, not only `derived_from`).
module: s19_app/tui/app.py
examples: (TC-B100-20, test_tc_b100_20_variant_append_carries_every_key_and_activates) a seeded project with every key → carry holds "batch", "assignments", "declared_regions", "gathered", "derived_from" as project-relative strings (holds at dc3b314)
examples: (AT-B100-20 Inc 8a arm, LLR-168.3) a project.json with active_document "patches/boost.json" → carry active_document "patches/boost.json" (target (8a))

S19TuiApp._rewrite_project_manifest
req: LLR-168.3
in: Path project_dir; Path placed; Optional[DerivedFrom] derived = None
out: bool ok
func: the one rewrite of the in-project writers: read once, refuse a manifest it cannot carry whole, else write through the seam with the carry (plus `derived` for a save-back). No own change in 8a beyond what _manifest_carry and the reader change.
module: s19_app/tui/app.py
modify: [I/O: project.json] (replace)
examples: (TC-B100-20, test_tc_b100_20_save_back_carries_every_key) a save-back into a project seeded with every key → ok `True`, active_variant "firmware_1", the other keys unchanged (holds at dc3b314 for the keys written before 8a)
examples: (AT-B100-20 Inc 8a arm) a project with active_document "patches/boost.json" → ok `True` and project.json still holds "patches/boost.json" (target (8a); at dc3b314 the unknown key refuses the rewrite and ok is `False`)

S19TuiApp._sync_loaded_file_to_project
req: LLR-168.3
in:
out: None
func: the Load-file variant append and MAC sync: place the loaded file into the open project, activate it, rewrite project.json with the carry. No own change in 8a; it is one of the three AT-B100-20 writers that must keep `active_document`.
module: s19_app/tui/app.py
examples: (AT-B100-20 arm 1) with P open and all five keys set, Load a new S19 → project.json keeps the five keys equal, 0 absolute paths, and names the new active_variant (target (8a) for the active_document key)
examples: (AT-B100-20 arm 2, test_tc_b100_20_mac_sync_carries_every_key) Load a MAC → the carried keys equal (holds at dc3b314 for four keys)

S19TuiApp._sync_loaded_a2l_to_project
req: LLR-168.3
in:
out: None
func: the A2L sync: place a loaded A2L into the open project and rewrite project.json with the carry. No own change in 8a; the third AT-B100-20 writer.
module: s19_app/tui/app.py
examples: (AT-B100-20 arm 3, test_tc_b100_20_a2l_sync_carries_every_key) Load an A2L with P open and all five keys set → the five keys equal, 0 absolute paths (target (8a) for the active_document key)

S19TuiApp.on_patch_editor_panel_save_back_decision
req: LLR-168.2, LLR-168.3, LLR-168.4
in: PatchEditorPanel.SaveBackDecision event
out: None
func: the Patch Editor save-back: writes the image, marks the change service saved, activates the written variant and rewrites project.json with the carry plus its derived_from. No own change in 8a; a fourth carry writer (TC-B100-20).
module: s19_app/tui/app.py
examples: (TC-B100-20, test_tc_b100_20_save_back_carries_every_key) a save-back as "firmware.s19" into a project seeded with every key → active_variant "firmware_1", the other keys unchanged (holds at dc3b314)

S19TuiApp._handle_load_project
req: LLR-170.3, HLR-170, LLR-169.6
in: Optional[str] name
out: None
func: Load project: validate, reset the session, read project.json, check files, attach the A2L, install the active or next valid variant, MAC, one summary line. 8a changes: after the A2L is attached, load `active_document` into the change service (through the Patch Editor load seam), and list a missing or unreadable document as a problem and continue.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._change_service] (replace)
examples: (AT-B100-08 / HLR-170 `p06` A) project.json active_document "patches/boost.json" with 1 entry → after Load the Patch Editor document is `patches/boost.json` with 1 entry (target (8a); P-8 at 1d677ba: editor doc `None`, entries `0`)
examples: (TC-B100-30, LLR-170.3) a symbol entry in the recorded document → resolved against the project's A2L, 0 unresolved (target (8a))
examples: (TC-B100-30) the recorded document missing → 1 problem, the project opens (target (8a))

S19TuiApp._reset_project_session
req: LLR-165.1, LLR-165.3
in:
out: int discarded
func: the one reset seam of a project load: rebinds the change service (empty document), clears the panel buffer and calls mark_loaded; returns the outgoing document's entry count. No change in 8a; the document reopen must run after it (it would wipe a document loaded earlier).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._change_service] (replace); [Data: PatchEditorPanel._dirty] (replace)
examples: (TC-B100-10, test_tc_b100_10_interim_discard_notice) P1 open with 1 entry, then Load P2 → discarded `1` and the status "Closed the Patch Editor document (1 entries); unsaved changes were not kept" (holds at dc3b314)

S19TuiApp._patch_editor_load
req: LLR-008.1, LLR-170.3
in: PatchEditorPanel panel; str path_text
out: None
func: the shared change-document load seam (typed path, dropdown, dirty-guard accept): ChangeService.load, report, mark_loaded on success, re-render. Passes no A2L context. Candidate seam for the 8a reopen.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp._change_service] (replace); [Data: PatchEditorPanel._dirty] (replace)
examples: (LLR-170.3 via the reopen) path_text "<P>/patches/boost.json" with 1 address entry → the document has 1 entry and [Data: PatchEditorPanel._dirty] `False` (target (8a) as a reopen; the seam itself holds at dc3b314)

ChangeService.load
req: LLR-003.4, LLR-141, LLR-170.3
in: str path_text; Path base_dir; Optional[dict] a2l_context = None
out: ChangeActionResult result
func: reads a v2 change or check JSON file into the owned document, replacing it; `a2l_context` `None` refuses every symbol entry. No change expected in 8a; the caller must pass the project's A2L context for LLR-170.3's symbol arm.
module: s19_app/tui/services/change_service.py
modify: [Data: ChangeService.document] (replace)
examples: (TC-B100-30, LLR-170.3) the recorded document with a symbol entry and the project's A2L context → ok `True`, 0 unresolved (target (8a) for the caller)
examples: (docstring, LLR-141) a2l_context `None` and a symbol entry → the entry is refused (holds at dc3b314)
