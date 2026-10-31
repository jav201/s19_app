# Code-Wire baseline — batch-100 Inc 8b slice at `ebe6d0c`

Scope: the functions on the Inc 8b paths (US-161, HLR-171, LLR-171.1–171.4, LLR-167.6 save-as arm, LED .63 (b) / .66): Save project (name guards → plan → refusals → folder → placements → gather → manifest), the single-MAC / single-A2L refusals and where the folder is created, project listing and load routing, the A2L-only load, and the in-project writers that LLR-171.4 counts (save-back, variant append, MAC sync, A2L sync, the manifest seam) with the guards they place through.

Example lines are taken from `01-requirements.md` (the AT / TC / LLR numeric pass thresholds and premises P-9, P-11, P-12) or from an existing test id; each names its source. A line marked "target (8b)" states what the requirement asks for and does not hold at `ebe6d0c`; a line marked "holds at ebe6d0c" is behaviour the requirement keeps. `func:` says "8b changes: …" where an Inc 8b requirement changes the function. Nodes with no "8b changes" are context: callers, guards and writers the change relies on.

## Nodes

S19TuiApp._handle_save_dialog
req: HLR-171, LLR-171.1, LLR-171.3, LLR-171.4, LLR-167.6, HLR-164, LLR-005.1
in: Optional[SaveProjectPayload] payload
out: None
func: Save project: name guards (HLR-164) over `self.workarea`, missing-source refusal, `project_dir = parent_resolved / cleaned`, reparse refusal of the target, image decision and plan (`_plan_project_save`), plan refusal, then `project_dir.mkdir`, then validate_project_files and the single-MAC / single-A2L refusals (rolled back by `_abort_save`), the plan's placements, the gather, the manifest write and the commit block. The parent folder is only checked with `is_dir()`. 8b changes: (a) refuse a parent that does not resolve to `self.workarea` before any folder (LLR-171.3); (b) the single-MAC / single-A2L refusals run before `mkdir`, as a plan-time decision (LED .66, LED .63 (b)); (c) on a save to a new name with an open project, copy every sub-folder file the plan names through `place_into_workarea`, each into its relative path, and paint the skipped links (LLR-171.1); (d) the free-space refusal before the folder exists (LLR-171.1).
module: s19_app/tui/app.py
modify: [I/O: project folder] (append); [Data: S19TuiApp.current_project_dir] (replace); [Data: S19TuiApp._variant_set] (replace)
examples: (AT-B100-09, P-9) open project P with `flows/f1.json`, `patches/boost.json`, `reports/r.md`, Save project as Q → Q holds "flows/f1.json", "patches/boost.json", "reports/r.md" (target (8b); P-9 at 1d677ba: Q tree "firmware.a2l", "firmware.s19", "project.json" only)
examples: (TC-B100-31, LLR-171.1) P with a top-level directory junction, a nested junction and a file symlink, saved as Q → 0 files copied through them, `3` skips listed in the status (target (8b))
examples: (TC-B100-31, LLR-171.1) a sub-folder total over the simulated free space → status holds "not enough free space", `0` folders created (target (8b))
examples: (TC-B100-33, LLR-171.3, P-11) parent_folder another installation's `.s19tool/workarea` → refused, `0` folders (target (8b): at ebe6d0c the folder is created, then the explicit-root placement guard refuses and `_abort_save` removes it — see baseline-notes C2)
examples: (TC-B100-33, LLR-171.3) parent_folder this work area spelled with a trailing separator or mixed case → saved, `1` listing (target (8b))
examples: (AT-B100-11, LLR-171.4, HLR-164(f)) typed name of a work-area folder that is a junction → status holds "link or junction", nothing written (holds at ebe6d0c: `_is_reparse_point(project_dir)` before the plan)
examples: (LED .66, LLR-005.1) MAC loaded, target merge project already holding a different `.mac` → status "Project already has a MAC file." with `0` folders created at any point (target (8b): at ebe6d0c the refusal runs after `mkdir` and the rollback removes the folder)
examples: (test_b100_save_image.py::_open_project_session docstring) the open project holding its own A2L, saved again → status "Project already has an A2L file." (holds at ebe6d0c; see baseline-notes C3)

S19TuiApp._plan_project_save
req: LLR-167.6, LLR-171.1
in: Path project_dir; str project_name; _ProjectImageStep image_step; bool derived = False; Optional[str] carried_active_document = None
out: SavePlan plan
func: builds the PlannedFile list (image, MAC, A2L, the Patch Editor document) with digests, the target kind (new, open project, merge) and the manifest keys, then calls plan_project_save. No sub-folder of the open project is planned. 8b changes: one walk of `current_project_dir` (when the target is not the open project) that prunes every `_is_reparse_point` directory and skips file links gives the sub-folder files, their total and the skipped links (LLR-171.1); the free-space refusal and the single-MAC / single-A2L refusals become plan refusals (LED .66).
module: s19_app/tui/app.py
examples: (TC-B100-59, test_tc_b100_59_open_project_unchanged) the open project P1 with `firmware.s19` and `firmware.mac` saved again → plan.target_kind "open project", rows image "keep", mac "keep", manifest "new" (holds at ebe6d0c)
examples: (TC-B100-59 Inc 8b arm, LLR-167.6 "one row per sub-folder with its file count") open project P with `flows/f1.json`, Q new → plan holds a sub-folder row for "flows" with count `1` (target (8b))
examples: (LLR-167.6 "computing a plan writes 0 bytes … computes 0 digests", test_tc_b100_59_planning_writes_nothing_and_hashes_no_payload) a plan computed → `0` bytes written (holds at ebe6d0c; 8b must keep it with the walk)

plan_project_save
req: LLR-167.6
in: Path target; str target_kind; Sequence[PlannedFile] files; str image; Sequence[str] manifest_keys; Optional[str] refusal = None
out: SavePlan plan
func: pure planner: one row per top-level file (and the document under its home) with its predicted landing name and action word, plus the project.json row; writes nothing and hashes nothing. SavePlan has no sub-folder row and no skipped-links field. 8b changes: one row per sub-folder with its file count and the skipped links (LLR-167.6), the sub-folder files predicted under their relative path; a refusal (free space, single MAC / A2L) keeps a row-less plan.
module: s19_app/tui/services/project_gather_service.py
examples: (TC-B100-59, test_tc_b100_59_fresh_folder) target `P1` new, files [image `firmware.s19`] → rows image "new" and manifest `project.json` "new" (holds at ebe6d0c)
examples: (TC-B100-59, test_tc_b100_59_refused_plan_writes_nothing) refusal set → rows `0` (holds at ebe6d0c)
examples: (TC-B100-59 Inc 8b arm) files with `flows/f1.json` and `reports/r.md` into a new Q → rows for "flows" and "reports", each count `1` (target (8b))

S19TuiApp._abort_save
req: LLR-164.4, LED .53
in: Path project_dir; bool created_project_dir; Sequence[Path] placed_files; Sequence[Path] created_dirs; Tuple save_state; Sequence[Tuple[Path, bytes]] manifest_restores = (); Sequence[Tuple[Path, bytes]] kept_copies = ()
out: None
func: rolls a failed Save project back: removes exactly the files and folders this save created, restores a replaced manifest and the in-memory state. Unchanged by 8b, but every sub-folder copy and every sub-folder 8b creates must join `placed_files` / `created_dirs`.
module: s19_app/tui/app.py
modify: [I/O: project folder] (clear)
examples: (HLR-167 threshold "a blocked change document → 0 files, 0 folders left") a failed save that created the folder → `0` folders left (holds at ebe6d0c)

_plan_row_mismatch
req: LLR-163.7, LLR-167.6
in: SavePlanRow row; PlacementResult placed
out: Optional[str] mismatch
func: checks one landed placement against its plan row; a mismatch aborts the save. 8b: each sub-folder copy is one more placement to check against its row (if sub-folder files get per-file rows).
module: s19_app/tui/app.py
examples: (TC-B100-59, test_tc_b100_59_landing_that_differs_from_its_row_rolls_back) a landing that differs from its row → a mismatch text, the save rolled back (holds at ebe6d0c)

S19TuiApp.list_projects
req: LLR-171.4, LLR-164.2
in:
out: List[str] projects
func: every direct child directory of `self.workarea` whose case-folded name is not a reserved home. `is_dir()` follows a junction; no reparse or containment check. 8b changes: skip a folder for which `_is_reparse_point` is true (checked before any resolve) and require `contained_in_workarea` (LLR-171.4).
module: s19_app/tui/app.py
examples: (test_b99_load_project.py:163) work area with `P1` and `P2` → projects "P1", "P2" (holds at ebe6d0c)
examples: (test_tc_b100_04_list_projects_omits_reserved_homes_casefolded) a reserved home in any case → not listed (holds at ebe6d0c)
examples: (AT-B100-11, TC-B100-62 Inc 8b arm) `workarea/evil` a junction into another work area's project → projects `0` entries named "evil" (target (8b))

S19TuiApp.action_load_project
req: LLR-178.3
in:
out: None
func: the Load project key: list_projects, then the LoadProjectScreen whose dismiss runs _route_load_project. Unchanged by 8b; the listing it shows is what AT-B100-11 reads.
module: s19_app/tui/app.py
examples: (test_b99_load_project.py:167) an empty work area → status "No saved projects found." (holds at ebe6d0c)

S19TuiApp._route_load_project
req: LLR-178.3
in: Optional[str] name
out: None
func: the Load dialog's router: runs _handle_load_project, then opens the Load-result panel when a new announcement was composed. The only production caller of _handle_load_project. Unchanged by 8b.
module: s19_app/tui/app.py
examples: (LLR-178.3) a cancelled pick, name `None` → no Load-result panel (holds at ebe6d0c)

S19TuiApp._handle_load_project
req: LLR-171.2, LLR-171.4, LLR-169.6, LLR-170.3, HLR-165
in: Optional[str] name
out: None
func: Load project: `project_dir = self.workarea / name`, exists check, validate_project_files, `No supported files in project` when there is no data file, the session reset, build_variant_set, the manifest, check_project_files, the A2L parse (`_load_a2l_data_with_cache`), choose_install_set (a second `No supported files` when no variant and no MAC), the document reopen, the image install loop, the announcement. No reparse or containment check on `project_dir`. 8b changes: (a) a project with no data file and one A2L resets the session, sets the project and `_variant_set = build_variant_set(name, [])`, attaches the A2L through the A2L load path and reports it (LLR-171.2); (b) neither data nor A2L → the `no data or A2L file` tokens; (c) refuse a project folder for which `_is_reparse_point` is true, before `resolve()`, and require `contained_in_workarea` (LLR-171.4).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project_dir] (replace); [Data: S19TuiApp._variant_set] (replace)
examples: (AT-B100-10, TC-B100-32, P-12) project with files "firmware.a2l", "project.json" → status "No supported files in project: P" (holds at ebe6d0c; RED side of AT-B100-10)
examples: (TC-B100-32, LLR-171.2) the same A2L-only project `p04` → `3` A2L tags, current_project set, current_file `None` (target (8b))
examples: (TC-B100-32, LLR-171.2) a folder whose `project.json` records no missing file and holds no data and no A2L → status holds "no data or A2L file" and "load a file and Save project" (target (8b))
examples: (TC-B100-62 Inc 8b arm, LLR-171.4) name `evil`, a junction into another work area → `0` loads (target (8b))

S19TuiApp._reset_project_session
req: HLR-165, LLR-165.1
in:
out: int discarded_entries
func: the one reset seam of a project load: clears the image, MAC and A2L attachments, the A2L path and data, rebinds ChangeService; returns the outgoing document's entry count. Unchanged by 8b; the A2L-only branch must call it (LLR-171.2 "reset the session").
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_a2l_path] (clear)
examples: (LLR-171.2) an A2L-only load → the reset runs before the A2L attach, so current_a2l_path is the project's A2L after the load, not the previous session's (target (8b))

choose_install_set
req: LLR-169.6
in: ProjectVariantSet variant_set; Optional[str] recorded; Sequence[Path] data_files; Sequence[Path] a2l_files; Sequence[str] unreadable = ()
out: InstallSet install
func: the load fallback rule: the recorded variant when valid, else the next valid one; then the MAC and the A2L. With no data file the variant and the MAC are `None` and the A2L is `a2l_files[0]`. Unchanged by 8b; the A2L-only branch reads its `a2l`.
module: s19_app/tui/app.py
examples: (LLR-171.2, p04) data_files `0`, a2l_files [`firmware.a2l`] → install.variant `None`, install.mac `None`, install.a2l "firmware.a2l" (holds at ebe6d0c by reading the code)

S19TuiApp._load_a2l_data_with_cache
req: LLR-170.3, LLR-169.9
in: Optional[Path] path
out: Optional[dict[str, Any]] data
func: parses an A2L (with the cache) and returns the payload. Called by _handle_load_project before the install. Unchanged by 8b.
module: s19_app/tui/app.py
examples: (TC-B100-32 threshold, p04) the project's `firmware.a2l` → a payload with `3` tags (holds at ebe6d0c by the threshold's source probe)

S19TuiApp.load_a2l_from_path
req: LLR-171.2, LLR-172.1
in: Path path
out: None
func: the standalone A2L load: resolve the path, refuse with "Project already has an A2L file." when `current_project` is set and the project already holds an A2L, copy into `workarea/temp` through copy_into_workarea, parse, set current_a2l_path to the temp copy, update the view. Unchanged by 8b unless the A2L-only branch reuses it as "the A2L load path" (see baseline-notes C4).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_a2l_path] (replace)
examples: (test_b100_save_image.py:904, locked "a2l") `firmware.a2l` from a folder outside the work area → current_a2l_path not `None` (holds at ebe6d0c)

S19TuiApp._sync_loaded_file_to_project
req: LLR-171.4, LLR-163.5, LLR-168.3
in:
out: None
func: the variant append and the MAC sync: `project_dir.mkdir(exist_ok=True)`, validate_project_files, place_into_workarea with `workarea_root=self.workarea`, then the manifest rewrite. Unchanged by 8b; two of the writers LLR-171.4 counts at 8b.
module: s19_app/tui/app.py
modify: [I/O: project folder] (append)
examples: (test_tc_b100_62_variant_append_root_refuses_another_workarea) the open project dir resolving into another work area → refused, `0` bytes written there (holds at ebe6d0c)
examples: (TC-B100-62 Inc 8b arm, LLR-171.4) open project `evil`, a junction into another work area, a new S19 loaded → `0` bytes written outside `self.workarea` (target (8b) as an app-level arm; the placement refusal holds)

S19TuiApp._sync_loaded_a2l_to_project
req: LLR-171.4, LLR-168.3
in:
out: None
func: the A2L sync: `project_dir.mkdir(exist_ok=True)`, skip when the project already has an A2L, place_into_workarea with `workarea_root=self.workarea`, then the manifest rewrite. Unchanged by 8b; one of the writers LLR-171.4 counts.
module: s19_app/tui/app.py
modify: [I/O: project folder] (append)
examples: (test_tc_b100_62_syncs_root_refuses_another_workarea) the project dir resolving into another work area → refused, `0` bytes written there (holds at ebe6d0c)

S19TuiApp.on_patch_editor_panel_save_back_decision
req: LLR-171.4, LLR-168.2, B99-I7
in: PatchEditorPanel.SaveBackDecision event
out: None
func: the save-back: `dest_dir = _active_project_dir() or self.workarea`, ChangeService.save_patched with `workarea_root=self.workarea`, then activate the file and rewrite the manifest. Unchanged by 8b; one of the writers LLR-171.4 counts.
module: s19_app/tui/app.py
modify: [I/O: project folder] (append)
examples: (TC-B100-62 Inc 8b arm, LLR-171.4) open project `evil`, a junction into another work area, save-back → `0` bytes written outside `self.workarea` (target (8b) as an app-level arm)

S19TuiApp._active_project_dir
req: LLR-171.4, LED .50
in:
out: Optional[Path] project_dir
func: the open project's folder, unresolved: `current_project_dir`, else `workarea / current_project`. Every in-project writer reads it. Unchanged by 8b.
module: s19_app/tui/app.py
examples: (LED .50 R3-2) current_project `P1`, current_project_dir `None` → project_dir ends "P1" under the work area, unresolved (holds at ebe6d0c by reading the code)

validate_project_files
req: LLR-005.1, LLR-171.2
in: Path project_dir
out: tuple(list[Path] data_files, list[Path] a2l_files, Optional[str] error)
func: lists the direct regular-file children of the project: S19/HEX/MAC as data, A2L apart; more than one MAC or A2L is an error. Its lists feed the single-MAC / single-A2L refusals in Save project and the A2L-only decision in Load. Unchanged by 8b.
module: s19_app/tui/workspace.py
examples: (P-12) folder with "firmware.a2l", "project.json" → data_files `0` items, a2l_files "firmware.a2l", error `None` (holds at ebe6d0c)

build_variant_set
req: LLR-005.6, LLR-171.2
in: str project_name; Sequence[Path] data_files; Optional[str] active_id = None
out: ProjectVariantSet variant_set
func: the project's variants from its S19/HEX data files, in deterministic order. LLR-171.2 calls it with an empty list for an A2L-only project. Unchanged by 8b.
module: s19_app/tui/workspace.py
examples: (LLR-171.2 negative control) project_name `P`, data_files `0` items → a variant set with `0` variants, not `None`, so the next Load file rewrites project.json (target (8b) for the caller; the function's empty-list result holds by reading the code)

place_into_workarea
req: LLR-163.1, LLR-171.4
in: Path source; Path destination; int max_size_bytes = DEFAULT_COPY_SIZE_CAP_BYTES; Optional[Path] workarea_root = None
out: PlacementResult placed
func: the one placement function: source and destination reparse checks, size cap, private staging, containment in this work area (`_guarded_destination` → contained_in_workarea), byte-identical reuse or the lowest free `_<N>`. Unchanged by 8b; LLR-171.1's sub-folder copies go through it.
module: s19_app/tui/workspace.py
modify: [I/O: destination folder] (append)
examples: (test_tc_b100_62_junction_destination_is_refused_nothing_written) a destination that is a junction into another work area → WorkareaContainmentError, `0` bytes written (holds at ebe6d0c)

contained_in_workarea
req: LLR-171.4, B100-I14
in: Path path; Path workarea
out: bool contained
func: true iff the path, after resolving every link and junction, is inside `workarea.resolve()`. Unchanged by 8b; LLR-171.4 adds list_projects and _handle_load_project as callers.
module: s19_app/tui/workspace.py
examples: (test_tc_b100_62_containment_predicate) a path under another `.s19tool/workarea` → contained `False` (holds at ebe6d0c)

_is_reparse_point
req: LLR-171.1, LLR-171.4, HLR-164
in: Path path
out: bool is_link
func: true when the path is a symbolic link or a Windows reparse point (junction); the path need not exist. Unchanged by 8b; LLR-171.1's walk prunes with it and LLR-171.4 adds list_projects and _handle_load_project as callers.
module: s19_app/tui/workspace.py
examples: (TC-B100-31, LLR-171.1) a directory junction inside P → is_link `True` (holds at ebe6d0c by the S-03 probe the requirement cites)

write_project_manifest
req: LLR-171.4, LLR-169.2
in: ProjectVariantSet variant_set; Path project_root; Path base_dir; Sequence[str] batch = (); Optional[Mapping[str, Sequence[str]]] assignments = None; Sequence[DeclaredRegion] declared_regions = (); Optional[Mapping[str, Sequence[str]]] gathered = None; Optional[Mapping[str, FileRecord]] files = None; Optional[Mapping[str, DerivedFrom]] derived_from = None; int schema_version = DEFAULT_SCHEMA_VERSION; Optional[str] active_document = None
out: tuple(Optional[Path] written, list[ValidationIssue] issues)
func: the manifest seam: serialize, `_check_destination_contained` with this app's work area (`ensure_workarea(base_dir)`), stage, `os.replace`, re-check after the replace. Unchanged by 8b; the eighth writer of LLR-171.4's threshold.
module: s19_app/tui/services/manifest_writer.py
modify: [I/O: project.json] (replace)
examples: (test_tc_b100_62_manifest_write_refuses_a_project_swapped_for_a_junction) project_root swapped for a junction → written `None`, `0` bytes written outside (holds at ebe6d0c)

## Entities

[I/O: project folder]
desc: `<workarea>/<name>/`: top-level data, MAC, A2L, project.json, and the sub-folders flows/, flowsets/, patches/, checks/, reports/, templates/, splits/
sequence:
  saveProject: S19TuiApp._plan_project_save → S19TuiApp._handle_save_dialog wins (mkdir) → validate_project_files (!) (the single-MAC / single-A2L refusals read after the folder exists) → place_into_workarea → write_project_manifest

[Data: S19TuiApp.current_project_dir]
desc: the open project's folder, stored unresolved under the work area (LED .50); the source folder of a save-as sub-folder walk
