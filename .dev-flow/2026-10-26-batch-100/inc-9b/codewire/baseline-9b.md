# Code-Wire baseline — batch-100 Inc 9b slice ("the Load dialog") on the 9a tree

Scope: the functions on the Inc 9b paths (HLR-173 … HLR-173e, LLR-173.1 … LLR-173.7, LLR-172.1n; E1-scope §3): the two Load dialogs 9b retires (`LoadFileScreen`, `LoadProjectScreen`), the keys and actions that open them, the two dismiss callbacks, the typed-path router and classifier, the project list and its folder check, the project load, the data and A2L loads with their recent-source record (CR9-1), the Workarea Files pick, the app's action gate, and the unchanged helpers the 9b providers will call (store read, work-area lister, kind map, scrubs, install rule). Base: the 9a tree, `4fef292` plus 9a's uncommitted source changes (sha256 prefixes `app.py` bbf04117fbf0, `screens.py` 49d6efdc73e2, `styles.tcss` 781f04ed2cc3, `workspace.py` 0af4b9248923). Line numbers are 9a-tree lines. The `styles.tcss` selectors are not functions: they are listed in baseline-notes "Selectors".

Example lines come from the probe `p9b` run on a scratch copy of this tree (baseline-notes "Probe"), from an existing test, or from a code read; each names its source. Every example states behaviour that holds on the 9a tree. `func:` says "9b changes: …" where an Inc 9b requirement changes or retires the function; a node with no "9b changes" is context the change relies on.

## Nodes

LoadFileScreen.compose
req: HLR-173, LLR-173.2, LLR-173.2c
in:
out: ComposeResult widgets
func: builds `Container#load_dialog.modal-dialog` with a title Label, `OsClipboardInput#load_path`, and `Container#loadfile_buttons` holding `Button#load_ok` ("Load") and `Button#load_cancel`. `AUTO_FOCUS = "#load_path"`. No list, no preview, no reason line, no BINDINGS (no `escape`). 9b changes: retired; replaced by `LoadDialog.compose` (VS-PA-3, Q9).
module: s19_app/tui/screens.py
examples: (probe p9b F1) `l` → stack `LoadFileScreen` on top, focus on `load_path` (holds on 9a tree)
examples: (P-20, code read) the dialog holds `0` list widgets and names no work-area file or recent source (holds on 9a tree; RED side of HLR-173)
examples: (probe p9b F2, P-18) `escape` on the dialog → the stack still ends in `LoadFileScreen` (holds on 9a tree; RED side of HLR-173e)

> callers (extractor): none listed

LoadFileScreen.on_button_pressed
req: HLR-173c, HLR-173d, LLR-173.1, LLR-173.2h, LLR-173.2l
in: Button.Pressed event
out: None
func: `#load_cancel` → `dismiss(None)`; `#load_ok` → `dismiss(Path(value))` with the stripped `#load_path` text; an empty value returns with no dismiss and no feedback. No validation in the dialog: every typed-path decision is the app's, after the dialog closed. Enter in `#load_path` posts `Input.Submitted`, which no handler on this screen reads. 9b changes: retired; `LoadDialog.action_load` / `action_cancel` (dismiss a `LoadChoice` only after `verdict` returned `None`).
module: s19_app/tui/screens.py
examples: (probe p9b F3, P-19) empty `#load_path`, `#load_ok` clicked → stack unchanged, `0` status lines (holds on 9a tree; RED side of HLR-173d)
examples: (probe p9b F4, P-19) `#load_path` = the path of `firmware.s19`, `enter` → stack unchanged, `current_file` `None` (holds on 9a tree; RED side of HLR-173c)
examples: (test_loadfilescreen_typing_a_realistic_path_is_not_truncated) a realistic path typed → `#load_ok` dismisses with a `Path` of the whole text (holds on 9a tree)

> callers (extractor): none listed

LoadProjectScreen.__init__
req: LLR-173.2a, LLR-173.4
in: list[str] projects
out: LoadProjectScreen screen
func: keeps the project names given by `action_load_project` (already `list_projects()` output). 9b changes: retired; `LoadDialog.__init__` takes callables (`rows`, `verdict`, `preview`) and `mode` / `highlight` instead of a list.
module: s19_app/tui/screens.py
examples: (probe p9b U5) projects `['[b]P', 'ab', 'c', 'E', 'j', 'n', 's']` → `7` rows (holds on 9a tree)

> callers (extractor): `S19TuiApp.action_load_project` (direct, :7447)

LoadProjectScreen.compose
req: LLR-173.3, LLR-173.2b, LLR-173.4l
in:
out: ComposeResult widgets
func: builds `Container#load_dialog.modal-dialog` with a title Label, `ListView#project_list` of `ListItem(Label(name))` for each project (markup ON, no scrub: the LLR-173.3 sink, `screens.py:712`), and `Container#loadproject_buttons` with `Button#project_ok` / `Button#project_cancel`. No highlight of the open project: the ListView starts at index `0`. No BINDINGS (no `escape`). 9b changes: retired; rows come painted from `app.py` (`painted_names`, markup off) into one `OptionList#load_list`.
module: s19_app/tui/screens.py
examples: (probe p9b U5, LLR-173.3 negative control) a project folder named `[b]P` → its row renders `"P"` with `1` span styled `b` (holds on 9a tree; RED side of LLR-173.3)
examples: (probe p9b U5) `p` → focus on `project_list`, index `0` (the first listed name, not the open project) (holds on 9a tree)
examples: (probe p9b U6, P-18) `escape` → the stack still ends in `LoadProjectScreen` (holds on 9a tree)

> callers (extractor): none listed

LoadProjectScreen.on_button_pressed
req: LLR-173.1, LLR-173.1a, LLR-173.2j
in: Button.Pressed event
out: None
func: `#project_cancel` → `dismiss(None)`; `#project_ok` → `dismiss(self.projects[index])` for the ListView's index (by index, never the label: CW-U-1); no index → returns. `enter` on the list posts `ListView.Selected`, which neither this screen nor the app reads for `project_list`: Enter in the list loads nothing. 9b changes: retired; Enter / `#load_ok` act on the list or the path field by focus recency (LLR-173.2f / .2g), and `Selected` never loads (LLR-173.2j).
module: s19_app/tui/screens.py
examples: (probe p9b U8) index `0` (`[b]P`), `#project_ok` clicked → stack `LoadResultScreen`, status "Loaded project '[b]P' -> firmware.s19 - variant 1 of 1, 1 problem - details: p", `current_project` "[b]P" (holds on 9a tree)
examples: (probe p9b U7) `down` then `enter` on `#project_list` → stack unchanged, `0` status lines, `current_project` `None` (holds on 9a tree)

> callers (extractor): none listed

S19TuiApp.action_load_file
req: LLR-173.2, LLR-173.1e
in:
out: None
func: the Load key (`ctrl+l` priority, `l`; palette entry "Load file"): pushes `LoadFileScreen()` with `_handle_load_dialog` as its dismiss callback. Runs also while a modal is on top (priority binding). 9b changes: push `LoadDialog(mode="path", …)` → `_handle_load_dialog`.
module: s19_app/tui/app.py
examples: (probe p9b F1) `l` → stack `['Screen', 'LoadFileScreen']` (holds on 9a tree)
examples: (probe p9b F5, LLR-173.2e) `ctrl+l` while `LoadFileScreen` is open → action `load_file` runs, stack `['Screen', 'LoadFileScreen', 'LoadFileScreen']` (holds on 9a tree; RED side of LLR-173.2e)

> callers (extractor): none listed

S19TuiApp.action_load_project
req: LLR-173.2a, LLR-173.2b, LLR-173.1e, LLR-173.4d
in:
out: None
func: the Projects key (`p`; `#ws_load_project_button`; palette entry "Load project"): `projects = self.list_projects()`; none → status "No saved projects found." and no dialog; else pushes `LoadProjectScreen(projects)` with `_route_load_project` as its dismiss callback. 9b changes: push `LoadDialog(mode="list", highlight=<open project>)` → `_handle_load_dialog`, also with 0 projects (the section paints `no projects`).
module: s19_app/tui/app.py
examples: (probe p9b U1, LLR-173.2a / .4d negative control) `p` in a fresh work area → stack `['Screen']`, status "No saved projects found." (holds on 9a tree)
examples: (probe p9b U5) `p` with 7 listed folders → stack `['Screen', 'LoadProjectScreen']` (holds on 9a tree)

> callers (extractor): `S19TuiApp.on_button_pressed` (direct, :17635)

S19TuiApp._route_load_project
req: LLR-173.1a, LLR-178.3
in: str? name
out: None
func: the Load project dialog's dismiss callback and the typed router's project branch: runs `_handle_load_project(name)`, then pushes `LoadResultScreen(announcement)` only when `_last_load_announcement` now holds a new object (identity). Unchanged by 9b: `_handle_load_dialog` routes a `project` choice here (LLR-173.1a).
module: s19_app/tui/app.py
examples: (probe p9b U8) name "[b]P" → one `LoadResultScreen` pushed (holds on 9a tree)
examples: (code read) name `None` (cancel) → `_handle_load_project(None)` returns at once, no announcement, no panel (holds on 9a tree)

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12936)

S19TuiApp._handle_load_dialog
req: LLR-173.1, LLR-173.1c, LLR-173.1d, LLR-173.1e
in: Path? path
out: None
func: `LoadFileScreen`'s dismiss callback: `None` → return; else logs `modal_dismiss_scheduled`, flushes the log, and defers `_load_path_from_user_input(path)` with `call_after_refresh`. One of two dialog callbacks today (`_route_load_project` is the other). 9b changes: the one router for `Optional[LoadChoice]` or a bare `Path` → project / workarea / recent / path (LLR-173.1a … .1f).
module: s19_app/tui/app.py
examples: (test_handle_load_dialog_defers_load_until_after_modal_dismiss, LLR-173.1d) a `Path` → `_load_path_from_user_input` scheduled with `call_after_refresh`, not run inside the dismiss (holds on 9a tree)
examples: (test_handle_load_dialog_none_path_skips_scheduling) `None` → `0` scheduled calls (holds on 9a tree)

> callers (extractor): none listed

S19TuiApp._load_path_from_user_input
req: LLR-173.1c, LLR-173.1f, LLR-173.5, LLR-172.1n
in: Path path
out: None
func: the typed-path router: `_typed_load_route(path)` → `project` → `_route_load_project(name)`; `a2l` → `load_a2l_from_path(path)`; `data` → `load_from_path(path)`; `refuse` → one status line from the six reason words, the typed text through `painted_names`, then `safe_text(...).plain`. The refusal is painted after the dialog closed (status line). Unchanged by 9b in body; the dialog's `verdict` (N2) runs `_typed_load_route` once more before dismiss (E1 §5 observation 1).
module: s19_app/tui/app.py
examples: (probe p9b U4) `<workarea>/E` (an empty folder) → status "Project NOT loaded: '<workarea>\E' is not a project — pick a project in the list." (holds on 9a tree)
examples: (probe p9b F6, CR9-1) `R\x.s19` typed, working directory elsewhere, `R\x.s19` under the base folder → status "Loaded x.s19" (holds on 9a tree)

> callers (extractor): `S19TuiApp.on_mount` (direct, :7228)

S19TuiApp._typed_load_route
req: LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e, LLR-173.4k
in: Path path
out: tuple(str action, str value)
func: classifies one typed path from metadata only, never raises: relative → `resolve_input_path`; `None` → `("refuse", "not found")`; a folder → `"not a supported file"`; else by suffix. Absolute → lexical match against the work area (`abspath`, `normcase`), outside: manifest or folder → `"outside"`, file by suffix; inside: `lstat` walk (`"link"`, `"unreadable"`, `"not found"`), one component, matched by `normcase` against `list_projects()` (`"not a project"` when unlisted), then the §1.3 content tail (regular non-link `project.json`, or `validate_project_files` finds data / A2L / an error) → `("project", on-disk name)`. Unchanged by 9b; after Q7 its `list_projects` match already applies §1.3, so the tail becomes a second line of defence.
module: s19_app/tui/app.py
examples: (probe p9b U4) `<workarea>/E`, `E` empty → `("refuse", "not a project")` (via the content tail today; via the list match after Q7) (holds on 9a tree)
examples: (probe p9a U3 re-read, code read) a relative folder → `("refuse", "not a supported file")` (LLR-172.5h) (holds on 9a tree)

> callers (extractor): `S19TuiApp._load_path_from_user_input` (direct, :12934)

S19TuiApp.list_projects
req: LLR-173.4, LLR-173.4a, LLR-173.2b
in:
out: list[str] projects
func: `sorted(self.workarea.iterdir())` (Windows path order: case-insensitive), skipping reserved homes (case-folded), on Windows a name ending in "." or " ", any folder `_project_folder_refusal` refuses, and anything not `is_dir()`. No content check: an empty folder, or one holding only `notes.txt`, is listed. Raises `OSError` when the work area cannot be listed (callers catch it). 9b changes: apply the §1.3 content test here (Q7, LLR-173.4a).
module: s19_app/tui/app.py
examples: (probe p9b U2, LLR-173.4a negative control) folders `ab` (manifest + s19), `E` (empty), `n` (`notes.txt`), `j` (manifest only), `s` (`x.s19`), `c` (`c.a2l`), `[b]P` → `['[b]P', 'ab', 'c', 'E', 'j', 'n', 's']` (holds on 9a tree; `E` and `n` are the RED side)
examples: (probe p9a U1) `ab` + empty `E` → `['ab', 'E']` (holds on 9a tree)
examples: (test_tc_b100_04_list_projects_omits_reserved_homes_casefolded) reserved homes in any letter case → `0` of them listed (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11714); `S19TuiApp._typed_load_route` (direct, :12871); `S19TuiApp.action_load_project` (direct, :7441)

S19TuiApp._project_folder_refusal
req: LLR-173.4, LLR-173.5d
in: Path folder
out: str? reason
func: the one "is this folder a project here" folder check (HLR-171b): not one plain component of the work area → "outside"; `lstat` absent → `None`; other `OSError` → "unreadable"; a link or reparse point → "link"; not contained → "outside"; else `None`. Reads no content. Unchanged by 9b.
module: s19_app/tui/app.py
examples: (code read, LLR-171.4c) a junction `workarea/evil` → "link"; `list_projects` leaves it out (holds on 9a tree)
examples: (code read) a plain empty folder `workarea/E` → `None` (no content test) (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11684); `S19TuiApp.list_projects` (direct, :12127) — unmarked sites: app.py:9647, app.py:9694 (2)

S19TuiApp._handle_load_project
req: LLR-173.1a, LLR-173.4a, LLR-173.6, LLR-173.6a
in: str? name
out: None
func: the project load: `None` → return; a missing folder → "Project not found: …"; a name `list_projects()` does not list (by `normcase`) → "Project NOT loaded: '<name>' is not a project — pick a project in the list."; `validate_project_files` error → that status; A2L checks; no data and no A2L → "has no data or A2L file" (manifest present) or "has no project.json" (absent) — both before the reset; then the reset, `build_variant_set`, `read_project_manifest`, `choose_install_set`, the install and the announcement (Load-result panel via `_route_load_project`). Unchanged by 9b in body; after Q7 the empty-folder arm moves from "has no project.json" to the "not a project" list match.
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project] (replace)
examples: (probe p9b U3, probe p9a U6) `E` (empty) → "Project NOT loaded: 'E' has no project.json — load a file and Save project.", `current_project` `None` (holds on 9a tree; after Q7: "is not a project — pick a project in the list.")
examples: (probe p9b U3) `n` (`notes.txt` only) → "… 'n' has no project.json — load a file and Save project." (holds on 9a tree; after Q7: "is not a project")
examples: (probe p9b U3) `j` (`project.json` only) → "Project NOT loaded: 'j' has no data or A2L file — load a file and Save project." (holds on 9a tree and after Q7: `j` stays listed)

> callers (extractor): `S19TuiApp._route_load_project` (direct, :7478)

S19TuiApp.load_from_path
req: LLR-172.1n, LLR-173.1b, LLR-173.1c, LLR-173.1f
in: Path path
out: None
func: the data load: `normalized = resolve_input_path(path, base_dir)` (working directory, then base folder, then repository root); `None` → "File not found: …"; unsupported suffix → "Unsupported file type: …"; `copy_into_workarea(normalized, workarea/temp)`; when `normalized` is not inside the work area → `record_recent_source(normalized)` (the resolved path, whichever fallback found it: CR9-1); then `_start_load_worker(copied)` and `refresh_files` on the next idle frame. 9b changes: no record when the source was found only through the relative fallback (LLR-172.1n, Q1).
module: s19_app/tui/app.py
modify: [I/O: recent store] (replace)
examples: (probe p9b F6, CR9-1 executed) `R\x.s19` typed, working directory elsewhere, file under the base folder → store `[('<base>\R\x.s19', 's19')]` (holds on 9a tree; RED side of LLR-172.1n)
examples: (code read, LLR-172.1 9a) a source inside the work area (`_handle_select_variant`) → `0` store writes (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_select_variant` (direct, :7611); `S19TuiApp._load_path_from_user_input` (direct, :12942)

S19TuiApp.load_a2l_from_path
req: LLR-172.1n, LLR-173.1b
in: Path path
out: None
func: the A2L load, synchronous: `resolve_input_path`; suffix check; the open-project guard ("Project already has an A2L file."); `copy_into_workarea` into `workarea/temp` (for a path already in `temp/` this is a self-copy through the byte-identical reuse); record when outside the work area (resolved path, CR9-1); `refresh_files`; parse; `current_a2l_path` = the temp copy; views; "A2L loaded: …"; project sync. 9b changes: same record rule as `load_from_path` (LLR-172.1n).
module: s19_app/tui/app.py
modify: [I/O: recent store] (replace); [Data: S19TuiApp.current_a2l_path] (replace)
examples: (probe p9b F7) `_load_from_item` with `w.a2l` in `temp/` → `1` `copy_into_workarea` call (`w.a2l`), status "A2L loaded: w.a2l", `0` new store entries (probe p9b F9) (holds on 9a tree)

> callers (extractor): `S19TuiApp._load_from_item` (direct, :13333); `S19TuiApp._load_path_from_user_input` (direct, :12939)

S19TuiApp._load_from_item
req: LLR-173.1b
in: ListItem item
out: None
func: the Workarea Files pick: `item.data` (the on-disk name) → `workarea/temp/<name>`; when it exists: an A2L suffix → `load_a2l_from_path(candidate)` (one self-copy); anything else → `load_selected_file(candidate)` in place (no copy; an unsupported suffix gives "Unsupported file type: …"). Reads `item.data`, never the label. 9b changes: its body is shared with the dialog's `workarea` choice (guess node G1); see baseline-notes "Surprises" 2 for the A2L copy against LLR-173.1b's "0 `copy_into_workarea` calls".
module: s19_app/tui/app.py
examples: (probe p9b F7) `w.s19` → `0` `copy_into_workarea` calls (holds on 9a tree)
examples: (probe p9b F7) `w.a2l` → `1` call (holds on 9a tree)
examples: (probe p9b F7, 9a C7) `w.a2l.json` → `0` calls, status "Unsupported file type: .json" (holds on 9a tree)

> callers (extractor): `S19TuiApp.on_list_view_selected` (direct, :13183)

S19TuiApp.check_action
req: LLR-173.2e
in: str action; tuple parameters
out: bool? allowed
func: gates app actions by the active window: `confirm_attention` only on Flow Execution; `page_next_context` / `page_prev_context` only on A2L / MAC; `hex_page_prev` / `hex_page_next` only on Workspace; everything else → `App.check_action`. No modal-screen test: `load_file`, `save_project`, `focus_palette`, `cycle_density` are allowed while a modal is on top. 9b changes: return `False` for those four while `isinstance(self.screen, LoadDialog)` (S-g).
module: s19_app/tui/app.py
examples: (probe p9b F5, LLR-173.2e executed) under `LoadFileScreen`: `ctrl+l` → `load_file` runs (stack depth `3`); `ctrl+s` → `save_project` runs (`SaveProjectScreen` on top); `ctrl+k` → `focus_palette` runs; `ctrl+d` → `cycle_density` runs, density `density-comfortable` → `density-compact` (4 of 4 run; holds on 9a tree; RED side of LLR-173.2e)

> callers (extractor): none listed — unmarked sites: window_help.py:1134, window_help.py:1145 (2)

S19TuiApp._build_palette_entries
req: LLR-173.2m
in:
out: tuple[PaletteEntry, ...] entries
func: one palette entry per action from `BINDINGS`, first binding of an action wins (its description), then `EXTRA_PALETTE_ENTRIES`. Unchanged by 9b (LLR-173.2m and the labels "Load" / "Projects" are deferred to Inc 12a, Q8).
module: s19_app/tui/app.py
examples: (code read) `load_file` → entry "Load file" (from the `ctrl+l` binding); `load_project` → entry "Load project" (holds on 9a tree)

> callers (extractor): none listed — unmarked sites: app.py:2767 (1)

S19TuiApp.refresh_files
req: LLR-173.3a, LLR-173.4b
in:
out: None
func: the main Workarea Files list: clears `#files_list`, `list_workarea_files(self.workarea)`, each row `ListItem(Label(safe_text(painted_names([path.name]))))` with `entry.data = path.name`. The pattern the dialog's file rows follow (painted label, on-disk value). Unchanged by 9b (C7 stays for `#files_list`).
module: s19_app/tui/app.py
examples: (probe p9b F8, 9a C7) `temp/` holding `w.a2l`, `w.a2l.json`, `w.s19`, `x.s19` → `4` rows, `w.a2l.json` included (holds on 9a tree)

> callers (extractor): `S19TuiApp.load_a2l_from_path` (direct, :13134); `S19TuiApp.load_from_path` (direct, :13075); `S19TuiApp.on_mount` (direct, :7195) — unmarked sites: app.py:10601, app.py:7327 (2)

S19TuiApp._parse_loaded_file
req: LLR-173.6b
in: Path path; list[Path]? a2l_files = None
out: LoadedFile? loaded
func: the parse used by the worker and by `load_selected_file`: S19 / HEX → parse, then `_merge_primary_with_existing_mac` (the current file's `mac_path`, `mac_records`, `mac_diagnostics` are kept; A2L = the new primary's or else the current one); MAC → `_merge_mac_with_existing_primary` (overlays the MAC on the current S19/HEX, keeps its A2L when the MAC has none). Reads `self.current_file` at parse time (worker thread). This is the "MAC as the install keeps it" of LLR-173.6b, not `_apply_prepared_load`, which only installs the merged `LoadedFile`. Unchanged by 9b.
module: s19_app/tui/app.py
examples: (code read, LLR-173.6b) MAC `m.mac` loaded, then data file `f.s19` → installed `LoadedFile` with `path` f.s19 and `mac_path` m.mac (holds on 9a tree)
examples: (code read) no current file, `f.s19` → no MAC, no carried A2L (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_load_project` (through an unmarked helper; 2 site(s)); `S19TuiApp._load_from_item` (through an unmarked helper; 1 site(s)); `S19TuiApp.load_from_path` (through an unmarked helper; 1 site(s))

S19TuiApp.on_mount
req: LLR-173.1c
in:
out: None
func: startup; when a command-line `load_path` was given → `_load_path_from_user_input(load_path)`. The second caller of the typed router: the dialog's verdict is not on this path, so startup refusals stay on the status line. Unchanged by 9b.
module: s19_app/tui/app.py
examples: (code read, E1 §3 "callers checked") startup `load_path` = a missing file → status "File NOT loaded: '…' not found — check the path." (holds on 9a tree)

> callers (extractor): none listed

S19TuiApp.on_button_pressed
req: LLR-173.2a
in: Button.Pressed event
out: None
func: the main screen's button router; `#ws_load_project_button` ("Load project (p)") → `action_load_project()`. Unchanged by 9b.
module: s19_app/tui/app.py
examples: (code read) `#ws_load_project_button` with 0 projects → status "No saved projects found." (holds on 9a tree; same path as probe p9b U1)

> callers (extractor): none listed

S19TuiApp.on_list_view_selected
req: LLR-173.2j
in: ListView.Selected event
out: None
func: routes `ListView.Selected` by list id: `files_list` → `_load_from_item(event.item)`; `sections_list`, the A2L filter menu, the settings menu. No `project_list` arm, so Enter in the Load project dialog's list does nothing (probe p9b U7). Textual posts `Selected` for a click and for `enter` alike. Unchanged by 9b; the dialog's `#load_list` is an `OptionList` whose `OptionSelected` must not load (LLR-173.2j).
module: s19_app/tui/app.py
examples: (TC-B99-34) the `#files_list` item with data "a b.s19" selected → that file loads (holds on 9a tree)

> callers (extractor): none listed

S19TuiApp._handle_select_variant
req: LLR-172.1n
in: str? variant_id
out: None
func: the variant switch: `load_from_path(descriptor.path)` with a path inside the open project folder; the record in `load_from_path` skips it (inside the work area). Unchanged by 9b.
module: s19_app/tui/app.py
examples: (code read, LLR-172.1 9a) the open project's second variant → `0` store writes (holds on 9a tree)

> callers (extractor): none listed

choose_install_set
req: LLR-173.6, LLR-173.6a
in: ProjectVariantSet variant_set; str? recorded; Sequence[Path] data_files; Sequence[Path] a2l_files; Sequence[str] unreadable = ()
out: InstallSet install
func: pure fallback rule of a project load (LLR-169.6): start at the recorded active variant when it is one of the set, else the first; the first variant not in `unreadable` wins (wrapping once); MAC = the first data file with a MAC suffix; A2L = the first A2L. Called by `_handle_load_project`; its docstring already names "the Load dialog preview (Inc 9b)" as a user. Unchanged by 9b.
module: s19_app/tui/app.py
examples: (code read, LLR-173.6) recorded "v2" in variants v1, v2 → variant v2 (holds on 9a tree)
examples: (code read, LLR-173.6a) recorded "v2", `unreadable` ("v2",) → variant v1 (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11869, :11910)

resolve_input_path
req: LLR-172.1n, LLR-173.1f
in: Path raw_path; Path base_dir
out: Path? resolved
func: strips spaces and quotes, `expanduser`; the candidate as typed when it exists (relative to the working directory, not resolved); else for a relative path `(base_dir / candidate).resolve()`, then `(repo_root / candidate).resolve()`; else `None`. The fallback hits return a resolved (link-followed) absolute path; the first hit returns the path as typed. Unchanged by 9b (`workspace.py` is outside the cap).
module: s19_app/tui/workspace.py
examples: (probe p9b F6, CR9-1) `R\x.s19`, working directory without `R`, base folder holding `R\x.s19` → `<base>\R\x.s19` (resolved) (holds on 9a tree)

> callers (extractor): `S19TuiApp._typed_load_route` (direct, :12798, :12810); `S19TuiApp.load_a2l_from_path` (direct, :13089); `S19TuiApp.load_from_path` (direct, :13033) — unmarked sites: app.py:5385, app.py:6579, app.py:6580, app.py:9455, io.py:419, crc_designer_view.py:1307, crc_config.py:361, crc_designer_model.py:920 … (9)

record_recent_source
req: LLR-172.1n, HLR-173b
in: Path path
out: bool replaced
func: records `os.path.abspath(str(path))` first in the per-user store (`%LOCALAPPDATA%\s19_app\recent_sources.json`), de-duplicated by `normcase(abspath)`, capped at 20, atomic replace; never raises; `False` on any skip. Takes no "how was it found" input, so LLR-172.1n's test lives in the caller. Unchanged by 9b.
module: s19_app/tui/workspace.py
modify: [I/O: recent store] (replace)
examples: (probe p9b F6) `<base>\R\x.s19` → `True`; store `[('<base>\R\x.s19', 's19')]` (holds on 9a tree)

> callers (extractor): `S19TuiApp.load_a2l_from_path` (direct, :13132); `S19TuiApp.load_from_path` (direct, :13065)

read_recent_sources
req: LLR-173.4c, LLR-173.4f, LLR-173.4g
in:
out: RecentSources sources
func: the bounded store read: entries (`RecentEntry(path, kind)`, newest first, at most 20) and `problem` (`None`, "too large", "could not be read"; a problem means 0 entries). Never raises; reads no source file. Unchanged by 9b; the dialog's recents section reads it (N1).
module: s19_app/tui/workspace.py
examples: (probe p9b F6/F9) after one outside load and three work-area picks → `1` entry, problem `None` (holds on 9a tree)

> callers (extractor): `record_recent_source` (direct, :2486)

recent_kind
req: LLR-173.4b, LLR-173.4h
in: Path path
out: str? kind
func: pure suffix map with Windows suffix rules: `.s19`/`.srec` → "s19", `.hex`/`.ihex` → "hex", `.mac` → "mac", `.a2l` → "a2l", else `None`. The loadable-suffix filter LLR-173.4b names. Unchanged by 9b.
module: s19_app/tui/workspace.py
examples: (code read) `w.a2l.json` → `None`; `w.A2L` → "a2l" (holds on 9a tree)

> callers (extractor): `read_recent_sources` (through an unmarked helper; 1 site(s)); `record_recent_source` (direct, :2456)

list_workarea_files
req: LLR-173.4b
in: Path workarea
out: list[Path] files
func: the one enumeration of `workarea/temp`: regular, non-link direct children, names ending in "." or " " skipped, sorted by `(casefold, name)`; any `OSError` → `[]`. No suffix filter. Unchanged by 9b; the dialog's files section filters its output by `recent_kind`.
module: s19_app/tui/workspace.py
examples: (probe p9b F8) `temp/` with `w.a2l`, `w.a2l.json`, `w.s19`, `x.s19` → all `4` (holds on 9a tree; the filter is the RED side of LLR-173.4b)

> callers (extractor): `S19TuiApp.refresh_files` (direct, :7319)

validate_project_files
req: LLR-173.4a, LLR-173.6
in: Path project_dir
out: tuple(list[Path] data_files, list[Path] a2l_files, str? error)
func: scans direct children that are files (`is_file()` follows links): S19 / HEX / MAC → data (sorted `(lower, name)`), A2L → a2l; more than one MAC or A2L → an error text. Raises `OSError` when the folder cannot be listed. With a regular `project.json`, the §1.3 content test of `_typed_load_route`'s tail. Unchanged by 9b.
module: s19_app/tui/workspace.py
examples: (probe p9b U2 setup) `n` holding `notes.txt` → `([], [], None)` (holds on 9a tree)
examples: (probe p9a U2) `temp` holding `firmware.s19` → data `['firmware.s19']` (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11743); `S19TuiApp._typed_load_route` (direct, :12898); `S19TuiApp.load_a2l_from_path` (direct, :13101) — unmarked sites: app.py:10107, app.py:10908, app.py:12569, app.py:12634, app.py:9920, project_gather_service.py:1626, variant_execution_service.py:2743 (7)

painted_names
req: LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3c
in: Sequence[str] names; int limit = PAINTED_NAME_LIMIT; int clip = 120
out: str painted
func: the batch's one name scrub: removes Cc, Cf, Zl, Zp characters, turns an unpaired surrogate into U+FFFD, clips each name to `clip` characters ("…"), joins at most `limit` names with ", " then ", and K more". Pure; markup is not parsed (the caller wraps it with `safe_text` or a markup-off widget). Unchanged by 9b.
module: s19_app/tui/services/project_gather_service.py
examples: (docstring doctest) `["a", "b‮c"]`, limit `1` → "a, and 1 more" (holds on 9a tree)

> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11686, :11718, :11735, :11775, :11776, :11805, :11810); `S19TuiApp._load_path_from_user_input` (direct, :12944); `S19TuiApp.refresh_files` (direct, :7321) — unmarked sites: app.py:10468, app.py:10480, app.py:10482, app.py:10499, app.py:10823, app.py:12277, app.py:12333, app.py:12334 … (20)

safe_text
req: LLR-173.3
in: str value; str style = ""
out: Text text
func: deletes C0 / C1 control code points and wraps the rest as a Rich `Text` (markup never parsed). Keeps U+202E and surrogates, which is why LLR-173.3 cites `painted_names` and not `safe_text` alone. Unchanged by 9b.
module: s19_app/utils.py
examples: (code read) `"[b]P"` → `Text` with plain "[b]P" and `0` spans (holds on 9a tree)


> callers (extractor): `S19TuiApp._handle_load_project` (direct, :11702, :11717, :11734, :11774, :11813, :11941, :11942); `S19TuiApp._load_path_from_user_input` (direct, :12966); `S19TuiApp.load_a2l_from_path` (through an unmarked helper; 18 site(s)); `S19TuiApp.on_button_pressed` (through an unmarked helper; 16 site(s)); `S19TuiApp.on_list_view_selected` (through an unmarked helper; 16 site(s)); `S19TuiApp.refresh_files` (direct, :7321) — unmarked sites: app.py:10089, app.py:10460, app.py:10466, app.py:10479, app.py:10498, app.py:10588, app.py:16222, app.py:16232 … (148)
## Entities

[Data: S19TuiApp.BINDINGS]
desc: the app's key table. Load: `ctrl+l` (priority, shown, "Load file") and `l` (hidden) → `load_file`; `p` (hidden, "Load project") → `load_project`; priority keys `ctrl+k` → `focus_palette`, `ctrl+d` → `cycle_density`, `ctrl+s` → `save_project` (also `s`). Priority bindings run under a modal screen (probe p9b F5). The palette and the key bar read it.

[Data: App.screen_stack]
desc: today two Load modals: `LoadFileScreen` (dismiss → `_handle_load_dialog`) and `LoadProjectScreen` (dismiss → `_route_load_project`); neither closes on `escape`. A priority key can stack a second modal on top (probe p9b F5).

[Data: App.focused]
desc: `LoadFileScreen` opens on `#load_path` (`AUTO_FOCUS`); `LoadProjectScreen` opens on `#project_list`, index 0. No focus-recency state exists (S-f is new).

[Data: S19TuiApp.current_project]
desc: the open project's on-disk name; `LoadProjectScreen` does not read it (no highlight of the open project, LLR-173.2b).

[Data: S19TuiApp.current_a2l_path]
desc: the A2L work copy in `workarea/temp`; written by `load_a2l_from_path`.

[I/O: project folder]
desc: direct children of the work area. `list_projects` lists any plain non-reserved folder; §1.3's content test (manifest, data, A2L) is applied only by `_typed_load_route`'s tail and, as refusals, by `_handle_load_project`.

[I/O: recent store]
desc: `%LOCALAPPDATA%\s19_app\recent_sources.json`; written by `record_recent_source` from `load_from_path` / `load_a2l_from_path` (outside sources only, resolved path), read by `read_recent_sources`. No reader in the UI on the 9a tree.

## Edges

[Outside: key l] ──▶ S19TuiApp.action_load_file
[Outside: key ctrl+l] ──▶ S19TuiApp.action_load_file
when: always, also with a modal on top (priority)
[Outside: key p] ──▶ S19TuiApp.action_load_project
when: the main screen has the focus chain (not priority)
[Data: S19TuiApp.BINDINGS] ──▶ S19TuiApp._build_palette_entries
[I/O: project folder] ──▶ S19TuiApp.list_projects
[I/O: recent store] ──▶ read_recent_sources
S19TuiApp.load_from_path ──▶ [I/O: recent store]
S19TuiApp.load_a2l_from_path ──▶ [I/O: recent store]
