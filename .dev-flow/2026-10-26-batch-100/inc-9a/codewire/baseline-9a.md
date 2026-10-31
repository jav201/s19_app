# Code-Wire baseline — batch-100 Inc 9a slice at `4fef292`

Scope: the functions on the Inc 9a paths (US-162, HLR-172, LLR-172.1–172.6, AT-B100-12 / AT-B100-13, PLAN row 9a: recent-sources store, shared work-area lister, project path routing, L-2): the Load file path (key → dialog → typed-path router → data load / A2L load → worker → success or error), every enumeration of the work area (the Workarea Files list, the project list, the Save project clash scan), the Workarea Files pick, the project load route with its folder check, and the helpers these rely on. No recent-sources store exists at `4fef292` (no `recent`, `LOCALAPPDATA` or `APPDATA` in `s19_app/`); the four NEW functions LLR-172.1 / 172.2 / 172.4 name (`recent_store_path`, `record_recent_source`, `read_recent_sources`, `list_workarea_files`) have no code and are not nodes here — see baseline-notes "Target functions with no code".

Example lines are taken from `01-requirements.md` (HLR-172 / LLR-172.x thresholds, premises P-15, P-24, S-01, S-06, S-07, S-12, S-16), from an existing test id, or from the probe `p9a` run on `4fef292` (baseline-notes "Probe"); each names its source. A line marked "target (9a)" states what the requirement asks for and does not hold at `4fef292`; a line marked "holds at 4fef292" is behaviour the requirement keeps or that was executed on the base. `func:` says "9a changes: …" where an Inc 9a requirement changes the function. Nodes with no "9a changes" are context: callers, routes and helpers the change relies on.

## Nodes

S19TuiApp.action_load_file
req: LLR-172.5, HLR-172
in:
out: None
func: the Load key (`l`): pushes LoadFileScreen with `_handle_load_dialog` as its dismiss callback. Unchanged by 9a (the unified dialog is US-163 / Inc 9b).
module: s19_app/tui/app.py
examples: (AT-B100-12) the engineer presses Load and types the work-area path of project `ab` → the dialog's dismiss reaches `_handle_load_dialog` with that path (holds at 4fef292)

LoadFileScreen.on_button_pressed
req: LLR-172.5
in: Button.Pressed event
out: None
func: `#load_cancel` dismisses `None`; `#load_ok` dismisses `Path(value)` with the stripped `#load_path` text, nothing on an empty value. No validation in the dialog: every typed-path decision is the app's. Unchanged by 9a (LLR-173.x keeps the dialog open on an invalid path at 9b).
module: s19_app/tui/screens.py
examples: (test_loadfilescreen_typing_a_realistic_path_is_not_truncated) a realistic path typed into `#load_path` → the field keeps the whole text; Load dismisses with a `Path` of it (holds at 4fef292)

S19TuiApp._handle_load_dialog
req: LLR-172.5
in: Optional[Path] path
out: None
func: returns on `None`; logs the phase boundary and defers `_load_path_from_user_input(path)` with `call_after_refresh`. The only dialog route into the typed-path router. Unchanged by 9a.
module: s19_app/tui/app.py
examples: (test_handle_load_dialog_defers_load_until_after_modal_dismiss) a path → the load is scheduled with `call_after_refresh`, not run inside the dismiss; path `None` → no load (holds at 4fef292)

S19TuiApp.on_mount
req: LLR-172.4, LLR-172.5
in:
out: None
func: startup: `refresh_files()` (the first Workarea Files paint) and, when `load_path` was given on the command line, `_load_path_from_user_input(load_path)`. Unchanged by 9a, but both 9a seams run here: the lister paints the startup list and a startup project path takes the new project route.
module: s19_app/tui/app.py
examples: (TC-B99-36, test_tc_b99_36_workarea_files_reads_the_load_folder) a fresh base folder → the Workarea Files list holds `0` items (holds at 4fef292)
examples: (LLR-172.5, consequence) startup `load_path` = the work-area path of project `ab` → project `ab` loaded (target (9a); at 4fef292 status "Unsupported file type: " by the same router, P-15)

S19TuiApp._load_path_from_user_input
req: LLR-172.5, HLR-172, LLR-172.1
in: Path path
out: None
func: the typed-path router: `resolve_input_path(path, self.base_dir)`; `None` → "File not found: …"; an A2L suffix → `load_a2l_from_path(path)`; a data suffix → `load_from_path(path)`; anything else (a folder has the empty suffix) → "Unsupported file type: <suffix>". No folder or project branch, no work-area resolution. 9a changes: (a) a resolved path that is a project folder of this work area, or that folder's `project.json`, loads that project (through `_handle_load_project`, see baseline-notes C3); (b) any other folder inside the work area → the `not a project` tokens; a folder outside → the `outside the work area` tokens; a file with no or an unsupported suffix → `not a supported file` (LLR-172.5); (c) a reserved home never loads (S-01).
module: s19_app/tui/app.py
examples: (P-15, probe p9a U3) the work-area path `…/.s19tool/workarea/ab` → status "Unsupported file type: " (holds at 4fef292; RED side of AT-B100-12)
examples: (P-15, probe p9a U3) `…/workarea/ab/project.json` → status "Unsupported file type: .json" (holds at 4fef292)
examples: (TC-B100-38, LLR-172.5) `ab`, `ab/project.json` and `ab` reached through a `..` segment → `3` loads of `ab` (target (9a))
examples: (probe p9a U3) the bare name `ab` typed with the base folder as working directory → status "File not found: ab" (holds at 4fef292: `resolve_input_path` tries the working directory, the base folder and the repository root, never the work area — see baseline-notes C2)
examples: (TC-B100-38, LLR-172.5, S-01) `temp`, `TEMP`, `patches` typed → `0` project loads, `0` files written (target (9a); bare names give "File not found: temp" at 4fef292 — probe p9a U3 — so a bare-name arm is not RED on base, C2)
examples: (TC-B100-38) an empty folder inside the work area → `1` line holding "not a project" (target (9a))
examples: (TC-B100-38) a folder outside the work area holding a `project.json` → `1` line holding "outside the work area", `0` project loads (target (9a))
examples: (TC-B100-38) `firmware` with no suffix, an existing file → `1` line holding "not a supported file" (target (9a); at 4fef292 "Unsupported file type: ")

S19TuiApp.load_from_path
req: LLR-172.1, LLR-172.3, HLR-172
in: Path path
out: None
func: the data load: `resolve_input_path`, suffix check, `copy_into_workarea(normalized, workarea/temp, workarea_root=self.workarea)` (a containment refusal → "Cannot load file: …"), then `_start_load_worker(copied)` and, on the next idle frame, `refresh_files()`. Returns before the parse: success or failure is known only in the worker. Also the variant-switch route (`_handle_select_variant`) with a path inside the open project. 9a changes: call `record_recent_source` for a source outside the work area after a successful load (LLR-172.1 "after a successful copy"; HLR-172 "loads successfully" — baseline-notes C1).
module: s19_app/tui/app.py
examples: (AT-B100-12, LLR-172.1) `examples/case_01_basic_valid/firmware.s19` loaded → the per-user store lists its absolute path, kind "s19" (target (9a))
examples: (LLR-172.1) 25 distinct outside loads → `20` entries, newest first; the same file twice → `1` entry (target (9a))
examples: (LLR-172.1) a source inside the work area (a project variant through `_handle_select_variant`) → `0` entries (target (9a))
examples: (LLR-172.1) a failed load → `0` entries (target (9a); see C1: a parse failure is reported by `_handle_load_error` after this function returned)
examples: (LLR-172.1, S-16) `LOCALAPPDATA` unset → `0` files written; `0` files named "recent_sources.json" under the base folder (target (9a))
examples: (TC-B99-34, test_tc_b99_34_pick_loads_the_picked_file_name) `a.s19` loaded through the dialog → the Workarea Files list holds "a.s19" (holds at 4fef292)

S19TuiApp.load_a2l_from_path
req: LLR-172.1, HLR-172
in: Path path
out: None
func: the A2L load: `resolve_input_path`, suffix check, the open-project guard ("Project already has an A2L file."), `copy_into_workarea` into `workarea/temp`, `refresh_files()`, parse, `current_a2l_path` = the temp copy, view refresh, "A2L loaded: …", then `_sync_loaded_a2l_to_project` when a project is open. Synchronous: success is known before it returns. Also called by `_load_from_item` with a path already in `workarea/temp`. 9a changes: call `record_recent_source` for a source outside the work area after the successful copy (LLR-172.1).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_a2l_path] (replace)
examples: (LLR-172.1) an A2L from a folder outside the work area loaded → `1` store entry with kind "a2l" (target (9a))
examples: (LLR-172.1) the Workarea Files pick of `x.a2l` (a path inside `workarea/temp`) → `0` store entries (target (9a))
examples: (LLR-172.1) a project open that already holds an A2L → status "Project already has an A2L file.", `0` store entries (target (9a); the refusal holds at 4fef292)

S19TuiApp._start_load_worker
req: LLR-172.1
in: Path path; Optional[list[Path]] a2l_files = None
out: None
func: the thread worker (`@work(thread=True, exclusive=True, group="load")`): parses the copied file; an exception or an unsupported result → `_handle_load_error` on the main thread; else `_prepare_load_payload`, then `_apply_prepared_load` and `set_progress(100, …)` on the main thread, then `_sync_loaded_file_to_project` when a project is open. Receives the work copy, not the source path. Unchanged by 9a unless the record moves to the success point (C1).
module: s19_app/tui/app.py
examples: (LLR-172.1, C1) a source that copies but fails to parse → `_handle_load_error` runs and `_apply_prepared_load` does not (holds at 4fef292 by reading the code)

S19TuiApp._apply_prepared_load
req: LLR-172.1
in: PreparedLoad prepared; Path path; float load_started
out: None
func: the main-thread install of a parsed load: the one point where a data load is known to have succeeded. Its `path` is the work copy in `workarea/temp`. Unchanged by 9a unless it becomes the record point (C1).
module: s19_app/tui/app.py
examples: (TC-B99-34) a valid `a.s19` → the install runs once and the status names the file (holds at 4fef292)

S19TuiApp._handle_load_error
req: LLR-172.1
in: Path path; Exception exc
out: None
func: the main-thread failure handler of the load worker: status and progress reset. Unchanged by 9a; "a failed load → 0 entries" is decided by whether the record runs before or after this point (C1).
module: s19_app/tui/app.py
examples: (LLR-172.1) a `.s19` source whose bytes do not parse → a failure status, `0` store entries (target (9a) for the store; the failure status holds at 4fef292)

S19TuiApp.refresh_files
req: LLR-172.4, LLR-172.6, HLR-172, LLR-162.3
in:
out: None
func: the Workarea Files list: clears `#files_list`, `sorted((workarea/temp).glob("*"))`, keeps `item.is_file()` (follows a file link; skips `.staging` only because it is a folder), appends `ListItem(Label(item.name))` with `entry.data = item.name`. `Label` parses markup by default (P-24). 9a changes: (a) build the list from `list_workarea_files(self.workarea)` — regular, non-link files of `temp/`, `.staging` excluded (LLR-172.4); (b) each label through `safe_text(item.name)` (LLR-172.6). `entry.data` stays the raw name, the pick's source.
module: s19_app/tui/app.py
examples: (AT-B100-13, TC-B100-39, LLR-172.6) files `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19` and a name holding U+009B in `temp/` → `4` rows whose plain text equals the name minus control characters, `0` spans, `0` control characters (target (9a))
examples: (HLR-172 negative control, P-24 QA-02 probe) `[bold]x.s19` → `1` span painted (holds at 4fef292; RED side of AT-B100-13)
examples: (TC-B100-37, LLR-172.4) a file link and `.staging` in `temp/` → `0` of them listed (target (9a); at 4fef292 a file link is listed because `is_file()` follows it — by reading the code, not run)
examples: (TC-B100-37, LLR-172.4) the AST census of `s19_app/` → `1` function enumerating `temp/` (target (9a); at 4fef292 this function is the one enumeration of `temp/` — baseline-notes "Listers")
examples: (TC-B99-36) after one load of `one.s19` → items "one.s19" only, no ".staging" (holds at 4fef292)

S19TuiApp._load_from_item
req: LLR-172.4, LLR-162.1
in: ListItem item
out: None
func: the Workarea Files pick: reads `item.data`, `candidate = workarea/temp/<name>`, when it exists an A2L suffix → `load_a2l_from_path(candidate)` (copies onto itself: byte-identical reuse), anything else → `load_selected_file(candidate)` in place. Unchanged by 9a; it must keep reading `item.data`, never the painted label (the safe_text label differs from the name when it held a control character).
module: s19_app/tui/app.py
examples: (TC-B99-34) the item with data "a b.s19" picked → that file loads (holds at 4fef292)
examples: (LLR-172.6 consequence) an item named with U+009B picked → the file of that exact name loads, not the scrubbed label's name (target (9a) to keep)

S19TuiApp.load_selected_file
req: LLR-172.1
in: Path path; Optional[list[Path]] a2l_files = None
out: None
func: the synchronous in-place load of a data file (no copy): parse, install. Reached by the Workarea Files pick and the project load. Unchanged by 9a; a work-area pick is not an outside load, so it records nothing.
module: s19_app/tui/app.py
examples: (LLR-172.1) a Workarea Files pick of `one.s19` → `0` store entries (target (9a))

S19TuiApp._handle_select_variant
req: LLR-172.1
in: Optional[str] variant_id
out: None
func: the variant switch: finds the descriptor, then `load_from_path(descriptor.path)` with a path inside the open project folder. Unchanged by 9a; the record in `load_from_path` must skip it (a source inside the work area).
module: s19_app/tui/app.py
examples: (LLR-172.1 "a source inside the work area → 0 entries") the open project's second variant selected → `0` store entries (target (9a))

S19TuiApp.action_load_project
req: LLR-172.5, LLR-178.3
in:
out: None
func: the Load project key (`p`): `list_projects()`; empty → "No saved projects found."; else LoadProjectScreen with `_route_load_project`. Unchanged by 9a.
module: s19_app/tui/app.py
examples: (test_b99_load_project.py:335) an empty work area → status "No saved projects found." (holds at 4fef292)

LoadProjectScreen.compose
req: LLR-173.3, HLR-172
in:
out: ComposeResult composed
func: the project list: `ListItem(Label(name))` for every name of `list_projects`, markup on (P-24, `screens.py:712`). Not changed by 9a: LLR-173.3 (Inc 9b) owns this sink; listed here because it is the second `Label(name)` sink P-24 names.
module: s19_app/tui/screens.py
examples: (P-24) a project folder named `[bold]p` → the row paints a style span (holds at 4fef292 by the premise; owned by LLR-173.3)

S19TuiApp._route_load_project
req: LLR-178.3, LLR-172.5
in: Optional[str] name
out: None
func: the Load project router: `_handle_load_project(name)`, then LoadResultScreen when a new announcement was composed. The only production caller of `_handle_load_project` at 4fef292. Unchanged by 9a; the typed project route either calls it (the Load-result panel opens) or calls `_handle_load_project` directly (no panel) — C3.
module: s19_app/tui/app.py
examples: (LLR-178.3) a cancelled pick, name `None` → no Load-result panel (holds at 4fef292)

S19TuiApp._handle_load_project
req: LLR-172.5, LLR-171.4, LLR-171.2, HLR-165
in: Optional[str] name
out: None
func: Load project: `project_dir = workarea / name`; `_project_folder_refusal` ("link", "unreadable", "outside" → "Project NOT loaded: …"); exists; validate_project_files; the A2L checks; neither data nor A2L → "has no data or A2L file" / "has no project.json"; then the session reset and the install. No reserved-home check: `temp` and `TEMP` load as projects. 9a changes: refuse any name `list_projects` would not list — a reserved home compared case-folded, a link, a non-project — before the reset (LLR-172.5, S-01).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project_dir] (replace)
examples: (S-01, probe p9a U4) name `temp`, `workarea/temp` holding `firmware.s19` → status "Loaded project 'temp'", current_project "temp" (holds at 4fef292; RED side of TC-B100-38's reserved arms)
examples: (S-01, probe p9a U5) name `TEMP` → status "Loaded project 'TEMP'" (holds at 4fef292)
examples: (TC-B100-38, LLR-172.5) names `temp`, `TEMP`, `patches` → `0` project loads, `0` session resets, `0` files written (target (9a))
examples: (probe p9a U6) name `E`, an empty folder → status "has no project.json" (holds at 4fef292)
examples: (TC-B100-62, test_tc_b100_62_load_refuses_a_junction_project) name `evil`, a junction → a line holding "is a link or junction", `0` resets (holds at 4fef292)

S19TuiApp.list_projects
req: LLR-172.5, LLR-171.4, LLR-164.2, LLR-162.2
in:
out: List[str] projects
func: every direct child of the work area, sorted, whose case-folded name is not a reserved home, that `_project_folder_refusal` passes and `is_dir()`. No content check: an empty folder is listed, unlike the §1.3 "Project" definition (holds a `project.json`, a data file or an A2L). 9a changes: none stated; LLR-172.5 makes it the predicate `_handle_load_project` refuses by ("any name `list_projects` would not list … a non-project"), which it does not compute today (C4).
module: s19_app/tui/app.py
examples: (TC-B99-35, test_tc_b99_35_reserved_homes_are_not_projects) empty folders `P1`, `P2` and every reserved home → projects "P1", "P2" (holds at 4fef292; an empty folder is listed)
examples: (probe p9a U1) `ab` with `project.json` and an empty `E` → projects "ab", "E" (holds at 4fef292)
examples: (§1.3 "Project", LLR-172.5 "a non-project") an empty `E` → not listed (target (9a) only if C4 is decided that way; it breaks TC-B99-35 as written)

S19TuiApp._project_folder_refusal
req: LLR-171.4, LLR-172.5
in: Path folder
out: Optional[str] reason
func: the one folder check of HLR-171b: `folder.parent` textually equal to `self.workarea` and a plain name, else "outside"; `os.lstat` (absent → `None`, other error → "unreadable"); link or reparse point → "link"; `contained_in_workarea` → "outside". No reserved-home and no content check. Unchanged by 9a unless the reserved-home / non-project test joins it (C4).
module: s19_app/tui/app.py
examples: (LLR-171.4) `workarea/evil`, a junction → reason "link" (holds at 4fef292)
examples: (S-01) `workarea/temp` → reason `None` (holds at 4fef292 by reading the code)
examples: (LLR-172.5 "`ab` reached through a `..` segment") a folder spelled `workarea/x/../ab` → reason "outside" because the parent text is not the work area (holds at 4fef292 by reading the code; the typed router must normalise first — C2)

S19TuiApp._handle_save_dialog
req: LLR-164.2, LLR-172.4
in: Optional[SaveProjectPayload] payload
out: None
func: Save project. Listed for one part only: the clash scan `for item in sorted(self.workarea.iterdir())` — a third enumeration of the work-area root, with its own "is a project" test (`project.json` is a file, or a child with a data or A2L suffix; not reserved; not a reparse point). Unchanged by 9a; it does not enumerate `temp/`, so TC-B100-37's census does not count it.
module: s19_app/tui/app.py
modify: [I/O: project folder] (append)
examples: (TC-B100-05, test_tc_b100_05_case_only_match_against_another_project_refused) a typed name differing only in case from another project's folder → refused (holds at 4fef292)

resolve_input_path
req: LLR-172.5
in: Path raw_path; Path base_dir
out: Optional[Path] resolved
func: strips spaces and quotes, `expanduser`; returns the candidate when it exists as typed (relative to the working directory, unresolved), else `base_dir / candidate` resolved, else the repository root's, else `None`. Never tries the work area; a relative existing path returns unresolved, so `..` segments stay. Unchanged by 9a unless the typed project route adds a work-area base (C2).
module: s19_app/tui/workspace.py
examples: (probe p9a U3) `ab` with the base folder as working directory and the project at `workarea/ab` → `None` (holds at 4fef292)
examples: (P-15) the absolute work-area path of `ab` → that path (holds at 4fef292)

copy_into_workarea
req: LLR-172.1, LLR-163.1
in: Path source; Path destination; int max_size_bytes = DEFAULT_COPY_SIZE_CAP_BYTES; Optional[Path] workarea_root = None
out: Path placed
func: one statement over `place_into_workarea(...).path`: every guard, the byte-identical reuse and the `_<N>` claim. Both load paths copy through it; "after a successful copy" (LLR-172.1) means after it returns. Unchanged by 9a; the store is not in a work area and must not be written through it.
module: s19_app/tui/workspace.py
modify: [I/O: workarea temp] (append)
examples: (TC-B99-34) `a.s19` from outside into `workarea/temp` → placed ends "a.s19" (holds at 4fef292)

contained_in_workarea
req: LLR-172.1, LLR-172.5, LLR-171.4
in: Path path; Path workarea
out: bool contained
func: true iff the path, after resolving every link, is inside `workarea.resolve()`. Unchanged by 9a; the natural test for "a source outside the work area" (LLR-172.1) and "a folder outside it" (LLR-172.5).
module: s19_app/tui/workspace.py
examples: (LLR-172.1) the example `examples/case_01_basic_valid/firmware.s19` against the test work area → contained `False` (holds at 4fef292 by reading the code)
examples: (LLR-172.1) `workarea/ab/firmware.s19` → contained `True` (holds at 4fef292 by reading the code)

_is_reparse_point
req: LLR-172.1, LLR-172.4
in: Path path
out: bool is_link
func: true for a symbolic link or a Windows reparse point; the path need not exist. Unchanged by 9a; LLR-172.1 checks the store folder with it before `os.replace`, LLR-172.4's lister skips links with it.
module: s19_app/tui/workspace.py
examples: (LLR-172.1) the store folder `%LOCALAPPDATA%\s19_app` replaced by a junction → is_link `True`, `0` writes (target (9a) for the writer; the predicate holds)

validate_project_files
req: LLR-172.5, LLR-005.1
in: Path project_dir
out: tuple(list[Path] data_files, list[Path] a2l_files, Optional[str] error)
func: lists the direct regular-file children of a folder: S19/HEX/MAC as data, A2L apart. It accepts any folder, `temp` included. Unchanged by 9a.
module: s19_app/tui/workspace.py
examples: (S-01, probe p9a U2) `workarea/temp` holding `firmware.s19` → data_files "firmware.s19", error `None` (holds at 4fef292; the S-01 probe the negative control cites)

is_windows_device_name
req: LLR-172.2, LLR-164.1
in: str name
out: bool is_device
func: the shared device-name predicate (CON, PRN, AUX, NUL, COM0–9, LPT0–9, superscript digits, CONIN$, CONOUT$; case-folded, any extension). Unchanged by 9a; LLR-172.2 reuses it per path component of a store entry.
module: s19_app/tui/workspace.py
examples: (TC-B100-35, LLR-172.2) the component `NUL.s19` of `C:\x\NUL.s19` → is_device `True` (holds at 4fef292 by the HLR-164 tests)

safe_text
req: LLR-172.6, LLR-116.7
in: str value; str style = ""
out: Text text
func: deletes every C0/C1 control code point, then wraps the rest as a literal `Text` (no markup). Unchanged by 9a; the label builder of LLR-172.6.
module: s19_app/utils.py
examples: (TC-B100-39) value `[bold]x.s19` → text plain "[bold]x.s19", `0` spans (holds at 4fef292 by LLR-116.7's tests)
examples: (S-06) a value holding U+009B → plain text without it (holds at 4fef292)

## Entities

[I/O: workarea temp]
desc: `<workarea>/temp/`: the work copies of every Load (data and A2L), the A2L JSON dump, and the private `.staging` folder; the folder the Workarea Files list enumerates and the Workarea Files pick reads
sequence:
  loadFile: S19TuiApp._load_path_from_user_input → S19TuiApp.load_from_path → copy_into_workarea wins → S19TuiApp._start_load_worker → S19TuiApp._apply_prepared_load (!) (success known here; the record point is undecided, C1)

[I/O: project folder]
desc: `<workarea>/<name>/`: a project folder; `temp` and the other reserved homes are direct children of the same work area and pass every folder check except the reserved-name test of the Save dialog and `list_projects`

[Data: S19TuiApp.current_a2l_path]
desc: the attached A2L; after an A2L Load it is the work copy in `workarea/temp`, never the source path the store records

[Data: S19TuiApp.current_project_dir]
desc: the open project's folder; a load of `temp` makes `temp` the open project at 4fef292 (S-01, probe p9a U4)
