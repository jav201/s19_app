# Code-Wire prototype — Inc 9b, group G-B (`s19_app/tui/app.py`)

Stage E2 of the `design-first-increment` pipeline for Inc 9b ("the Load dialog"). Graph only: no stub, mark or other change in `s19_app/` of any tree; the 9a worktree is read-only. New functions are nodes whose `func:` starts with "new". Base: the 9a tree (`4fef292` plus 9a's uncommitted changes, read 2026-10-31); line numbers are 9a-tree lines of `s19_app/tui/app.py` unless another file is named.

Inputs: `../E1-requirements-draft.md` (LLR-173.2m removed by Q8), `../E1-scope.md` (§3 slice A1–A7, N1–N5, G1–G3, callers), `../E1-rulings.md` (Q1–Q10 binding), `interfaces-9b.md` (FIXED; this file proposes no change to it), the 9a format model `inc-9a/codewire/proto-9a-app.md`.

Conventions (as 9a): `W` = this work area (`<base>/.s19tool/workarea`); `<tmp>` = a temporary folder outside `<base>`; `<lad>` = the test `LOCALAPPDATA`; "the store" = `<lad>/s19_app/recent_sources.json`; `LC(k, v)` = `LoadChoice(k, v)`; `pn(x)` = `painted_names([x])` (the one category scrub: Cc, Cf, Zl, Zp removed, an unpaired surrogate as U+FFFD, clipped to 120 characters ending in `…`). A preview line written `● x` is the tuple `("x", True)`; the `● ` prefix is the dialog's (S-d). "Session digest" is the E1 tuple (`current_file.path`, image SHA-256, `current_project`, `current_a2l_path`, MAC path). Every example states the 9b target unless it says "holds on the 9a tree".

## G1–G3 decisions

| Guess | Decision | Reason |
|---|---|---|
| G1 `_load_workarea_file(name)` | **Keep** (new node; `_load_from_item` becomes a 3-line wrapper) | LLR-173.1b says the `workarea` choice loads "as the Workarea Files list's pick of that name loads it". One body makes that equality structural. Inlined, the router would hold a second copy of the 7-line body, and only the twin-digest test (B87) would catch drift. |
| G2 `_typed_refusal_tokens(reason)` | **Inline as data**: module constant `_TYPED_REFUSAL_TOKENS` (reason word → token pair), read by `_load_dialog_verdict` only | It is one dictionary lookup, so a function adds nothing. The status-line sentences of `_load_path_from_user_input` stay as 9a wrote them: 4 of the 6 sentences do not contain the token verbatim ("is not a supported file", "is outside the work area", "passes through a link or junction", "is not a project"). Unifying them would re-pin 9a's TC-B100-3x strings. So CR9-7 (one refusal table) stays in the backlog, and 9b does not close it. |
| G3 guard for the priority keys | **Keep, in the existing `S19TuiApp.check_action`** (`app.py:8034`), not in the four actions | `check_action` already gates actions by window (batch-97 I-11), so this is one condition in one place, against four separate edits. Textual 8.2.8 `run_action` returns `False` when `check_action` is false (`textual/app.py:4245-4248`). `_check_bindings` then tries the next binding, so the key reaches the dialog's own chain instead of an app action (see F-4). |

## Owned nodes (19) and context (3)

- **10 changed:** `action_load_file`, `action_load_project`, `_handle_load_dialog`, `_handle_load_project` (F-12, R2-N2), `list_projects`, `_typed_load_route` (step 11, F-3, and the inside-W branch, S9b-7), `load_from_path`, `load_a2l_from_path`, `_load_from_item`, `check_action`.
- **8 new:** `_load_dialog_rows`, `_load_dialog_verdict`, `_load_dialog_preview`, `_file_preview_marks`, `_load_workarea_file` (G1), `_folder_holds_project` (F-3), `_list_project_files` (R2-N2), `_a2l_admission` (A9b-R2-6).
- **1 data node:** the module constants `_TYPED_REFUSAL_TOKENS` (G2), `_RECENT_PROBLEM_STEPS` and `_LOAD_DIALOG_INERT_ACTIONS`.
- **Context (unchanged, with new callers):** `_route_load_project`, `_load_path_from_user_input`, `choose_install_set`.
- **A1 `BINDINGS`: unchanged.** Q8 removed LLR-173.2m, so the labels stay "Load file" / "Load project".

**Imports (app.py):**
- `LoadChoice` and `LoadDialog` join the `.screens` import; `LoadFileScreen` and `LoadProjectScreen` leave it (Q9).
- `read_recent_sources`, `recent_kind`, `RECENT_PROBLEM_TOO_LARGE` and `RECENT_PROBLEM_UNREADABLE` join the `.workspace` import.
- `PureWindowsPath` joins the `pathlib` import.
- Every other name is already imported: `painted_names`, `read_project_manifest`, `manifest_is_damaged`, `build_variant_set`, `PROJECT_DATA_EXTENSIONS`, `A2L_EXTENSIONS`, `list_workarea_files`, `_is_reparse_point`, `work`, `workspace`. `validate_project_files` leaves the import (the 9b slice lists through `_list_project_files`, R2-N2).

## Nodes

S19TuiApp.action_load_file
req: LLR-173.2, LLR-173.1e, LLR-173.6l, HLR-173
in:
out: None
func: changed (`app.py:7329`). `self.logger.info("Load file action triggered.")`, then `self.push_screen(LoadDialog(mode="path", highlight=self.current_project, rows=self._load_dialog_rows, verdict=self._load_dialog_verdict, preview=self._load_dialog_preview), self._handle_load_dialog)`. The open project is passed in path mode too, so the list already has its highlight when the engineer tabs into it.
callers: `ctrl+l` (priority) and `l` (`BINDINGS` :2122, :2127); palette entry `load_file` (`_build_palette_entries`, reads `BINDINGS`, unchanged).
module: s19_app/tui/app.py
examples: B01 (LLR-173.2, HLR-173, root key `l`) main screen, press `l` → screen stack depth `2`, top `LoadDialog`, `mode == "path"`, `focused.id == "load_path"`. Press `escape`, then `ctrl+l` → the same. `#load_list` exists in the dialog. Result `3` of `3`. Negative control (code read, 9a tree): `LoadFileScreen` has no `#load_list` → RED.
examples: B02 (LLR-173.1e, AST census of `app.py`) every `push_screen` whose first argument is a `LoadDialog(...)` call → `2` sites (`action_load_file`, `action_load_project`), each with callback `self._handle_load_dialog`, and `0` other callbacks. Negative control (9a tree): `action_load_project` pushes `LoadProjectScreen` with `self._route_load_project` → RED. A mutation that gives `action_load_project` its own callback → RED.
examples: B03 (LLR-173.6l, seam S-b) the dialog's `rows`, `verdict` and `preview` are the bound methods `app._load_dialog_rows`, `app._load_dialog_verdict` and `app._load_dialog_preview` (identity on `__func__`, `3` of `3`). The dialog class references `0` names imported from `s19_app.tui.services.*` or `s19_app.tui.workspace` (that census is G-A's).

S19TuiApp.action_load_project
req: LLR-173.2a, LLR-173.2b, LLR-173.1e
in:
out: None
func: changed (`app.py:7439`). It no longer calls `list_projects` and has no early return: `self.logger.info("Load project action triggered.")`, then `self.push_screen(LoadDialog(mode="list", highlight=self.current_project, rows=…, verdict=…, preview=…), self._handle_load_dialog)`, with the same three callables as `action_load_file`. The status line `No saved projects found.` goes; the empty projects section paints the `no projects` token line (N1). `highlight` is the on-disk name, because 9a's E3 R3 stores the listed spelling in `current_project`.
callers: `p` (`BINDINGS` :2135); `on_button_pressed` `#ws_load_project_button` (:17632); palette entry `load_project`.
module: s19_app/tui/app.py
examples: B04 (LLR-173.2a) projects `ab` and `cd`: press `p` → `focused.id == "load_list"`. Click `#ws_load_project_button` → the same. Work area with `0` projects, press `p` → the dialog opens; the projects section holds the disabled line `no projects — ctrl+s saves a project`; `0` status lines `No saved projects found.`. Result `3` of `3`. Negative control (9a tree): with 0 projects the old action paints `No saved projects found.` and opens nothing → RED.
examples: B05 (LLR-173.2b) projects `A`, `P`, `Z`, with `P` open → `LoadDialog(highlight="P")`, and the highlighted option's choice is `LC("project", "P")`. No project open → `highlight=None` → `A` highlighted. `0` projects and `W/temp/x.s19` → `highlight=None` → the `x.s19` row highlighted. Result `3` of `3`; the row choice is G-A's. Negative control: a dialog that always highlights row 0 → the `P` arm highlights the `Projects` heading or `A` → RED.
examples: B06 (LLR-173.2b, spelling) project `ab` loaded by typing `W/AB` → `current_project == "ab"` (9a R3) → `highlight="ab"`, which equals the row value `"ab"` → that row is highlighted.
examples: B07a (census, re-pin) `tests/test_b99_load_project.py:335` waits for `No saved projects found.` after a click on `#ws_load_project_button` → RED at 9b; re-pin it to the `no projects` token line (LLR-173.2a).

S19TuiApp._handle_load_dialog
req: LLR-173.1a, LLR-173.1b, LLR-173.1c, LLR-173.1e, LLR-173.1f, HLR-173b, HLR-173c, HLR-173e, LLR-173.2k, LLR-173.2l, LLR-166.1, LLR-178.3, AT-B100-14
in: Optional[LoadChoice] result
out: None
func: changed (`app.py:12969`); the one router. Steps:
- (1) `result is None` → `self._rehome_focus_after_load()`, then return (A9b-03: LLR-166.1 requires the focus re-home on a close; the function only reads `default_screen.focused` and leaves a healthy focus alone). Nothing is scheduled, so the session is unchanged (escape, Cancel).
- (2) `self.logger.info("Load phase boundary: modal_dismiss_scheduled kind=%s value=%r", choice.kind, choice.value)`, then `self._flush_logger()`. No test pins the old `path=%s` text (`grep -rn modal_dismiss_scheduled tests tools` → `0`).
- (3) Dispatch, always through `self.call_after_refresh`, so Textual pops the modal before any load work runs (the reason the 9a code already gives at :12999):
  - `project` → `self._route_load_project(choice.value)` (LLR-173.1a: the route that opens the Load-result panel, LLR-178.3);
  - `workarea` → `self._load_workarea_file(choice.value)` (G1);
  - `path` and `recent` → `self._load_path_from_user_input(Path(choice.value))`, with the text unchanged (LLR-173.1c, LLR-173.1f). `Path()` makes no filesystem call. A recorded entry is `os.path.abspath` output, so `str(Path(v)) == v` holds for every accepted entry.
- An unknown `kind` cannot occur, because `LoadKind` is a closed `Literal`. There is no else arm (rule 2).
- Inc 10 inserts the load question at this seam (LLR-174.4, informative); 9b adds no question.
callers: `action_load_file`, `action_load_project` (dismiss callback); `tests/test_tui_app.py:1254`, `:1288` and `tests/test_b100_active_variant.py:210`, re-pinned to `LoadChoice("path", str(p))` (A9b-08); cancel/escape dismiss `None`.
module: s19_app/tui/app.py
examples: B07 (LLR-173.1a, LLR-178.3) `LC("project", "ab")` → `1` scheduled call `(_route_load_project, ("ab",))`. After the refresh: `current_project == "ab"`, `1` `LoadResultScreen` on the stack, and the status log holds `Loaded project 'ab'` (`2` of `2`). Negative control: a mutation that schedules `_handle_load_project` directly → `0` Load-result panels → RED.
examples: B08 (LLR-173.1a boundary, LLR-172.5g) `LC("project", "AB")` with `ab` on disk (Windows only; such a value can only come from a test) → `_handle_load_project` matches the listing → `current_project == "ab"`, `1` panel.
examples: B09 (LLR-173.1b, data) `LC("workarea", "x.s19")` → `1` scheduled call `(_load_workarea_file, ("x.s19",))` → `current_file.path == W/temp/x.s19`, `0` calls of `copy_into_workarea` (spy), and the names in `W/temp` are unchanged. Negative control: a mutation that routes `workarea` through `self._load_path_from_user_input(W/temp/x.s19)` → `load_from_path` → `1` `copy_into_workarea` call → RED. Declared: the name-set arm passes on that mutant (G-005 identical-file reuse), so the spy is the RED.
examples: B10 (LLR-173.1b, A2L, A9b-05, S9b-5) `LC("workarea", "c.a2l")` → the A2L goes through `load_a2l_from_path` (the 9a route, including `copy_into_workarea` — an identical-file reuse that keeps the 256 MB cap and the link re-check), status `A2L loaded: c.a2l` (the name painted through `painted_names`). The session digest equals a `#files_list` pick of `c.a2l` on a twin fixture, and the names in `W/temp` are unchanged (`2` of `2` with B09). Negative control: a mutation that loads the A2L in place with no cap → a 300 MB `big.a2l` parses on the event loop → RED (S9b-6).
examples: B11 (LLR-173.1c) `LC("path", "<tmp>/a.s19")` → `1` data load (`current_file.path.name == "a.s19"`). `LC("path", "<tmp>/b.a2l")` → `1` A2L attach (status `A2L loaded: b.a2l`). `LC("path", "<W>/ab")` (absolute) → project `ab` loaded and `1` `LoadResultScreen`. Result `3` of `3`. Negative control: a mutation that schedules `load_from_path(Path(value))` for `path` → the `<W>/ab` arm paints `Unsupported file type: ` and loads nothing → RED.
examples: B13 (LLR-173.1f, HLR-173b) store entry `C:\…\src\fw.s19` → `LC("recent", that text)` → `_load_path_from_user_input(Path(text))`. `_typed_load_route` takes the absolute branch, finds the path outside `W` with suffix `.s19`, and returns `("data", "")` → `load_from_path`. The work copy `W/temp/fw.s19` holds bytes equal to the source, and the store's first entry is that path again (the 9a record, LLR-172.1b). A recent `C:\…\src\cal.a2l` → `1` A2L attach. A recent `C:\…\gone\fw.s19` that is missing, with `<base>\fw.s19` present, routed directly → step (1) `resolve_input_path` returns `None` for an absolute missing path → status `File NOT loaded: 'C:\…\gone\fw.s19' not found — check the path.`, `0` loads. Result `4` of `4`. In the dialog, the verdict refuses that arm first (B56). Negative control: a mutation that routes a recent by `Path(PureWindowsPath(v).name)` → the base-folder fallback loads `<base>\fw.s19` → RED.
examples: B14 (HLR-173e, LLR-173.2k, LLR-173.2l, LLR-166.1, A9b-03) `escape` with the focus on each of `#load_path`, `#load_list`, `#load_preview` and `#load_ok`, plus a click on `#load_cancel` → the router receives `None` `5` times → `_rehome_focus_after_load()` runs on each `None`, `0` scheduled calls, the session digest unchanged, the store's SHA-256 unchanged, `0` status lines. The focus moves to the displayed window's target, not the old widget: focus an `Input` (`search_input`), then `ctrl+l`, then `escape` → the focus is on the window's target (`files_list`), not the `Input`; the same from the P-16 shape (the hidden Split / Join table holds the focus) → the focus is on the displayed window's target (LLR-166.1, TC-B100-12).
examples: B15 (HLR-173c, the router half of LLR-173.2f / LLR-173.2g) the 12 dismissals of HLR-173c's threshold reach the router as 9 row choices (`project`, `workarea` and `recent` × 3 triggers) and 3 `LC("path", "<tmp>/a.s19")` → 9 + 3 loads of the matching item. The list/path precedence is decided in G-A (S-f).
examples: B16 (AT-B100-14, the G-B half of the chain) in `LOCALAPPDATA=<lad>`, type `<repo>/examples/case_01_basic_valid/firmware.s19` → loaded and recorded. Start a new app instance with the same `<lad>` and press `l`; the recent section holds `firmware.s19 (s19)`. `tab` into the list, move to that row, press `enter` → the verdict is `None` → `LC("recent", "<repo, absolute>\examples\case_01_basic_valid\firmware.s19")` → `current_file` holds a work copy equal to the example's bytes, and the store's first entry is that path. Next, `p` and highlight the save-back project → the preview's `●` names equal the Loaded panel after `enter` (B67). Then `escape` → digest unchanged.

S19TuiApp.list_projects
req: LLR-173.4, LLR-173.4a, LLR-172.5, LLR-172.5b, LLR-172.5g
in:
out: List[str] projects
func: changed (`app.py:12096`); Q7: the §1.3 content test moves here. Steps (1)–(4) are unchanged:
- (1) `sorted(self.workarea.iterdir())`. An `OSError` here propagates, as on the 9a tree, and every caller catches it (`_typed_load_route` step 9, `_handle_load_project`, `_load_dialog_rows`).
- (2) Skip a reserved home (case-folded).
- (3) Skip a name ending in a dot or a space on Windows (E3 R14).
- (4) Skip a folder `_project_folder_refusal` refuses (a link, an unreadable entry), then any non-folder (`item.is_dir()`).
- (5, new) `held = self._folder_holds_project(item)`. `held is False` → skip (LLR-173.4a). `True` → list it. `None` (the content could not be read) → **list it**. This is a fail-open listing: an unreadable folder may be a project, and its preview (N4) and its typed route (`_typed_load_route` step 11) both say `could not be read`. It also keeps 9a's TC-B100-38 arm "route: validate_project_files" passing (F-3).
- Order is unchanged, and the names are the on-disk spellings.
- Cost per child, on the UI thread: 1 `lstat` (step 4), plus 1 `lstat` of `project.json`, plus at most 1 listing of the folder (a folder with a regular `project.json` is not listed). Estimated under 20 ms for 50 local project folders; not measured. E4 logs the elapsed time once at dialog open.
callers: `_load_dialog_rows` (new), `_typed_load_route` step (9), `_handle_load_project` (:11714). `action_load_project` is no longer a caller. Plus 7 test files (E1 §3).
module: s19_app/tui/app.py
examples: B17 (LLR-173.4a) `W` holds `e` (empty) and `n` (only `notes.txt`) → `0` rows. One folder holding only `project.json`, one only `x.s19` and one only `c.a2l` → `1` row each. Result `5` of `5`. A typed `<W>/e` → `not a project` / `pick a project in the list` (B52). Negative control (code read, 9a tree): steps (1)–(4) list `e` and `n` → RED.
examples: B18 (LLR-173.4) `W` holds `ab`, `cd`, `temp`, `patches` and `jx` (a junction to `ab`) → `["ab", "cd"]`. The junction arm is Windows only. Negative control: a mutation that lists `W` with `iterdir` and no `list_projects` → `temp`, `patches` and `jx` appear → RED.
examples: B19 (fail-open, TC-B100-38 holds) project `cd` holds `firmware.s19` and no `project.json`, and `_list_project_files` raises `PermissionError` (injected, R2-N4) → `cd` is listed (`held is None`). The typed `<W>/cd` → step 9 matches `cd` → step 11 → `("refuse", "unreadable")` → `1` status line holding `could not be read` and `check that the folder can be opened, then load again`. This is 9a's test, unchanged and passing.
examples: B20 (Q7 reverse census, `grep -rn list_projects tests` on the 9a tree, read and not run) **3 tests list empty folders and expect them**, and each turns RED at 9b: `tests/test_tui_app.py:367` (`Alpha`, `Zulu` empty), `tests/test_tui_helpers.py:132` (`ProjectA`, `ProjectB` empty), and `tests/test_b99_load_project.py:163` TC-B99-35 (`P1`, `P2` empty). The re-pin writes one `.s19` into each listed folder. Unaffected: `test_b100_save_guards.py:403` (the `realproject` holds `a.s19`), `test_b100_project_homes.py:1253` and `:1292` (saved projects), and `test_b100_recents.py:2525` and `:2579` (folders holding a data file). The 19 files that drive `LoadProjectScreen` are re-pinned anyway (Q9); E4 re-runs this census over them.
examples: B21 (requirement conflict RC-1, see F-1) `_handle_load_project("E")`, where `E` is an empty folder: the 9a listing step (LLR-172.5g) runs before `validate_project_files`, and `E` is no longer listed → `Project NOT loaded: 'E' is not a project — pick a project in the list.`, `0` resets. LLR-171.2e (Inc 8b) asked for `no project.json` tokens there → it is retired (E2 F-1), and the TC-B100-32 `[no project.json]` arm (`tests/test_b100_project_homes.py:1022-1046`) is re-pinned to `is not a project` / `pick a project in the list`.

S19TuiApp._list_project_files
req: LLR-173.4n, LLR-173.4a, LLR-173.6, LLR-173.6d, HLR-173a
in: Path folder
out: tuple[list[Path] data_files, list[Path] a2l_files]
func: new (R2-N2). The one link-safe listing of a project folder, shared by the preview and the install: one `os.scandir(folder)` with `follow_symlinks=False`, collecting each entry where `entry.is_file(follow_symlinks=False)` and the name's suffix is in `PROJECT_DATA_EXTENSIONS` (into `data_files`, which includes MAC) or `A2L_EXTENSIONS` (into `a2l_files`). A link, a directory or any other kind is skipped, so a linked `.s19` / `.mac` / `.a2l` is neither listed nor installed (LLR-173.4n). It reads metadata only, writes nothing; an `OSError` propagates to the caller's catch (`_folder_holds_project` → `None`, the preview → `could not be read`, `_handle_load_project` → LLR-173.1g).
callers: `_folder_holds_project` (2); `_load_dialog_preview` (project branch); `_handle_load_project` (R2-N2, in place of `validate_project_files`).
module: s19_app/tui/app.py
examples: B101 (LLR-173.4n, R2-N2) project `P` holds `a.s19` and a symlink `b.s19` (to a regular file), with `active_variant` `b` → `data_files == [a.s19]`, `a2l_files == []` (the link skipped). The preview shows 1 variant row (`a.s19`) with 1 `●`; after `enter` 1 install (`a.s19`) and 0 opens of the link target (1 of 1). Negative control: a helper that follows links → 2 rows → RED.
examples: B102 (R2-N3) a folder holding only `m.mac` → `data_files == [m.mac]`, `a2l_files == []` (MAC counts as data), so `_folder_holds_project` returns `True`.

S19TuiApp._a2l_admission
req: LLR-173.6, HLR-173a
in: Path a2l_path
out: Optional[str] reason
func: new (A9b-R2-6). The one A2L admission rule, lifted from `app.py:11752-11790`: `os.lstat(a2l_path)`, a regular file, not a reparse point, and within `DEFAULT_COPY_SIZE_CAP_BYTES` → `None` (admissible); otherwise the reason word (`link`, `too large`, …). The preview and `_handle_load_project` both call it, so the A2L the preview marks is exactly the A2L the install keeps (HLR-173a); no second copy of the rule survives in either caller.
callers: `_load_dialog_preview` (the A2L mark); `_handle_load_project` (the A2L arm).
module: s19_app/tui/app.py
examples: B103 (A9b-R2-6) an A2L of `DEFAULT_COPY_SIZE_CAP_BYTES + 1` bytes → the reason word (the preview leaves it unmarked, B77). A regular under-cap A2L → `None` (marked). A linked A2L → the link reason (unmarked). Result `3` of `3`.

S19TuiApp._folder_holds_project
req: LLR-173.4a, LLR-172.5, LLR-172.5b
in: Path folder
out: Optional[bool] held
func: new. This is the one app-side copy of §1.3 (Q7: one definition for the list, the pick match and the typed route). It is lifted out of `_typed_load_route` step 11 (:12885-12903) with the same tests in the same order:
- (1) `os.lstat(folder / PROJECT_MANIFEST_NAME)`. A regular file that is not a reparse point → `True`. Any `OSError` falls through to (2), as step 11 does today.
- (2) `data_files, a2l_files = self._list_project_files(folder)` (R2-N2): return `True` when either list is non-empty — a data, MAC or A2L file (R2-N3: the scan counts MAC). Links are not followed (LLR-173.4n). An `OSError` → `None`.
- (3) otherwise → `False`.
- It reads metadata and at most one folder listing, writes nothing, and never raises an `OSError`.
callers: `list_projects` step (5); `_typed_load_route` step (11).
module: s19_app/tui/app.py
examples: B22 (§1.3 arms) a regular `project.json` → `True`, with `0` `_list_project_files` calls (spy). A `project.json` that is a directory, beside `x.s19` → `True`, through (2). Only `x.s19` → `True`. Only `c.a2l` → `True`. 2 MAC files only → `True` (the scan counts MAC as data, R2-N3). Empty → `False`. Only `notes.txt` → `False`. `_list_project_files` raises `PermissionError` → `None`. The `project.json` `lstat` raises `PermissionError` and the folder holds `x.s19` → `True`. Result `9` of `9`.

S19TuiApp._typed_load_route
req: LLR-172.5, LLR-172.5b, LLR-173.5b, LLR-173.5e
in: Path path
out: tuple[str, str] route
func: changed, step (11) (F-3) and the inside-W branch (S9b-7). Lines :12885-12903 become `folder = self.workarea / name`, then `held = self._folder_holds_project(folder)`: `True` → `("project", name)`; `None` → `("refuse", "unreadable")`; `False` → `("refuse", "not a project")`. The `False` arm is reachable only through a race, because a listed name already passed the same test in `list_projects`. Inside-W branch (S9b-7): the two `return ("a2l"/"data", "")` lines move after the lstat walk and are taken only when the last `lstat` is `S_ISREG`; a folder named `x.s19` then takes `("project", name)` when the folder is listed, or the `not a project` refusal when it is not (S9b-7 R2). Steps (0)–(9) and every return value are otherwise unchanged, and it still never raises.
callers: `_load_path_from_user_input` (unchanged); `_load_dialog_verdict` (new).
module: s19_app/tui/app.py
examples: B23 (holds, the 9a examples) `W/a2lonly` → `("project", "a2lonly")`. `W/empty` → `("refuse", "not a project")`, now at step (9), because `empty` is no longer listed; the result is the same. `W/locked` with `_list_project_files` raising (R2-N4) → listed by fail-open → step (11) `None` → `("refuse", "unreadable")`. Every 9a `_typed_load_route` example in `proto-9a-app.md` returns the same tuple.

S19TuiApp.load_from_path
req: LLR-172.1n, HLR-172, LLR-172.1a
in: Path path
out: None
func: changed; one condition on the 9a record step (:13064-13066), CR9-1, Q1. Before the step: `typed = Path(str(path).strip().strip('"')).expanduser()` and `via_fallback = normalized.is_absolute() and not typed.is_absolute()`. This is pure, with no filesystem call. `resolve_input_path` (`workspace.py:2022-2036`) returns the typed candidate unchanged when it exists, so the result is relative exactly when the typed text is relative. Only its base-folder or repository-root fallback returns an absolute (`.resolve()`d) path for a relative text. The step becomes `if not contained_in_workarea(normalized, self.workarea) and not via_fallback:` followed by the unchanged record and warning. When `via_fallback` holds and the source is outside `W`: `self.logger.info("Recent source not recorded (found through the fallback): %r", str(normalized))`, at INFO, so the threshold's "0 `Recent sources not updated` warnings" holds. No status line. The two lines repeat in `load_a2l_from_path`, as the 9a record step already does (no single-use helper, rule 2).
callers: unchanged (`_load_path_from_user_input`, `_handle_select_variant` :7606).
module: s19_app/tui/app.py
modify: [I/O: recent-sources store] (unchanged when found through the fallback)
examples: B24 (LLR-172.1n arm 1, Windows only) working folder `Wd` ≠ base folder `B`, and `B\j` is a junction to `R`. Typed `j\x.s19` → `normalized = (B/j/x.s19).resolve() = R\x.s19` (absolute) while the typed text is relative → `via_fallback`. Result: `1` load, `0` calls of `record_recent_source` (spy), the store's SHA-256 unchanged, `0` warnings holding `Recent sources not updated`, and `1` INFO line `Recent source not recorded (found through the fallback)`.
examples: B25 (LLR-172.1n arm 2) typed `fw.s19`, present only in `B` → `1` load, the store unchanged.
examples: B26 (LLR-172.1n arm 3, control) the same relative `fw.s19` with working folder `B` → found as typed (relative), `via_fallback` false → `1` entry whose path is `os.path.abspath("fw.s19")` = `B\fw.s19`.
examples: B27 (LLR-172.1n arm 4, control, Windows only) typed absolute `B\j\x.s19` → `1` entry `B\j\x.s19`; the link is not followed (LLR-172.1a, G1 `abspath`). Arms B24–B27: `4` of `4`.
examples: B28 (LLR-172.1n negative control) executed probe on the 9a tree (`review-increment-017.md` CR9-1): typed `j/x.s19` → the store holds `R\x.s19` → RED. A mutation that drops `and not via_fallback` → B24 records `R\x.s19` → RED.
examples: B29 (boundary) typed `~\x.s19` → `expanduser` makes the candidate absolute, the fallback never runs, and the source is recorded as found (`1` entry).

S19TuiApp.load_a2l_from_path
req: LLR-172.1n
in: Path path
out: None
func: changed; the same two lines on its record step (:13131-13133).
callers: `_load_path_from_user_input` (unchanged); `_load_workarea_file` (the A2L arm, restored by A9b-05).
module: s19_app/tui/app.py
modify: [I/O: recent-sources store] (unchanged when found through the fallback)
examples: B30 (LLR-172.1n, A2L arm; proposed for TC-B100-34, F-6) typed relative `cal.a2l`, present only in `B`, from working folder `Wd` → status `A2L loaded: cal.a2l`, the store's SHA-256 unchanged. The same file typed absolute → `1` entry `B\cal.a2l`, kind `a2l`. Negative control: the condition removed in this copy only → `1` entry → RED. The requirement's 4 arms all run through `load_from_path`.

S19TuiApp._load_dialog_rows
req: HLR-173, LLR-173.3, LLR-173.3a, LLR-173.3b, LLR-173.3d, LLR-173.4, LLR-173.4b, LLR-173.4c, LLR-173.4d, LLR-173.4e, LLR-173.4f, LLR-173.4g, LLR-173.4h, LLR-173.4j, LLR-173.4l, LLR-173.4m, LLR-173.6l, LLR-173.7, LLR-172.4
in:
out: list[LoadRow] rows
func: new; the `rows` callable (S-c), called by the dialog on mount, on the event loop. It returns `(section_id, painted plain label, choice)` triples in list order. Each section starts with its heading row (`choice None`) and holds either loadable rows or one token line (`choice None`). Section ids are `"projects"`, `"workarea"` and `"recent"`. Steps:
- (1) `("projects", "Projects", None)`. Then `names = self.list_projects()`:
  - `OSError` → `("projects", "could not be read — check that the folder can be opened, then load again", None)` (F-2: LLR-173.4m);
  - else each name → `("projects", pn(name), LC("project", name))`;
  - `0` names → `("projects", "no projects — ctrl+s saves a project", None)`.
- (2) `("workarea", "Work area", None)`. Then `files = [p for p in list_workarea_files(self.workarea) if recent_kind(p) is not None]` (the one lister, CR9-11; `recent_kind` maps exactly the suffixes the loaders take, 9a seam S10) → each `("workarea", pn(p.name), LC("workarea", p.name))`. `0` files → `("workarea", "no work-area files — l loads a file", None)`.
- (3) `("recent", "Recent", None)`. Then `store = read_recent_sources()`, which never raises:
  - `store.problem` set → `("recent", f"{store.problem} — {_RECENT_PROBLEM_STEPS[store.problem]}", None)`;
  - else `0` entries → `("recent", "no recent sources", None)`;
  - else each entry → `("recent", f"{pn(PureWindowsPath(e.path).name)} ({e.kind})", LC("recent", e.path))`. `PureWindowsPath` is pure, so this makes no filesystem call on `e.path` (LLR-173.4j) and gives the same name on the Linux CI.
- Every label goes through the one scrub; the dialog paints it with markup off (S-c).
callers: `LoadDialog` on mount (G-A), through `action_load_file` / `action_load_project`.
module: s19_app/tui/app.py
examples: B31 (HLR-173 list half, AT-B100-14) the fixture holds projects `ab` and `cd`, the reserved `temp` and `patches`, the junction `jx`, `W/temp` with `a.s19` and `c.a2l`, and a store of 3 entries `C:\s\fw.s19` (s19), `C:\s\cal.a2l` (a2l) and `C:\s\m.mac` (mac). The rows are exactly: `("projects","Projects",None)`, `("projects","ab",LC("project","ab"))`, `("projects","cd",LC("project","cd"))`, `("workarea","Work area",None)`, `("workarea","a.s19",LC("workarea","a.s19"))`, `("workarea","c.a2l",LC("workarea","c.a2l"))`, `("recent","Recent",None)`, `("recent","fw.s19 (s19)",LC("recent","C:\s\fw.s19"))`, `("recent","cal.a2l (a2l)",…)`, `("recent","m.mac (mac)",…)`. That is 3 sections and `2 + 2 + 3` loadable rows.
examples: B32 (HLR-173, LLR-173.3d) project `[b]P` → row `("projects", "[b]P", LC("project", "[b]P"))`: the label's plain text is `[b]P`, and the dialog paints `0` spans (G-A, S-c).
examples: B33 (LLR-173.3) projects `[b]P`, `[@click=app.bell]Q`, `x` + U+202E + `R` and `a` + U+009B + `S` → labels `[b]P`, `[@click=app.bell]Q`, `xR` and `aS`; `0` characters of category Cc, Cf or Cs; values are the 4 on-disk names. Result `4` of `4`. The U+009B arm is not run where the volume refuses the name. Negative control: a mutation with label `safe_text(name).plain` (C0/C1 only) → `xR` keeps U+202E → RED.
examples: B34 (LLR-173.3a) the six hostile names of LLR-172.6 with `.s19` → `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19`, `ab.s19`, `xgpj.s19` and `a` + U+FFFD + `b.s19`. A 130-character name → a 120-character label ending in `…`. Result `7` of `7`. Negative control: a mutation with label = name and markup on (G-A) → `[bold]x.s19` paints 1 span → RED.
examples: B35 (LLR-173.3b) store entries `C:\x\[bold]a.s19`, `C:\x\[link=y]b.hex` and `C:\x\[@click=app.bell]c.a2l` (each accepted by the 9a read) → labels `[bold]a.s19 (s19)`, `[link=y]b.hex (hex)` and `[@click=app.bell]c.a2l (a2l)`, `0` spans. Result `3` of `3`.
examples: B36 (LLR-173.3d) the U+009B file `a` + U+009B + `S.s19` and the 130-character file → each choice's `value` is the full on-disk name, not the label. After `enter`, `current_file.path.name` equals each on-disk name, and `[b]P` gives `current_project == "[b]P"`. Result `3` of `3`. Negative control: a mutation with `LC("workarea", label)` → `W/temp/aS.s19` is absent → `_load_workarea_file` loads nothing → RED.
examples: B37 (LLR-173.4b, CR9-11, LLR-172.4) `W/temp` holds `a.s19`, `b.hex`, `c.a2l`, `d.a2l.json`, `e.txt` and `.staging/` → 3 file rows `a.s19`, `b.hex`, `c.a2l`, in lister order. A runtime spy on `os.scandir`, `os.listdir`, `Path.iterdir` and `Path.glob` during one dialog open → `1` enumeration of `W/temp` (the `os.scandir` in `list_workarea_files`). `W` itself is listed once by `list_projects`, which skips `temp` by its reserved name before any content test, and each project folder without `project.json` is listed once by `_folder_holds_project`. The widened census (string literal `temp` in any case) → `1` enumerating function. Result `3` of `3`. Negative controls: `(self.workarea / "temp").iterdir()` in this node → census `2`, spy `2` → RED. No suffix filter → `5` rows → RED.
examples: B38 (LLR-173.4c) a store of 3 entries → 3 rows in stored order. A store of 20 → 20 rows. A store where the read refuses 1 of 3 entries → 2 rows. Result `3` of `3`. Negative control: rows sorted by path → order differs → RED.
examples: B39 (LLR-173.4d) `0` projects → exactly one projects row after the heading: `("projects", "no projects — ctrl+s saves a project", None)`, which is disabled (LLR-173.2i, G-A).
examples: B40 (LLR-173.4e) an empty `W/temp` → `("workarea", "no work-area files — l loads a file", None)`. A `W/temp` holding only `d.a2l.json` → the same line. Result `2` of `2`. Negative control: the token line written only when `list_workarea_files` returns `[]` → the `d.a2l.json` arm paints no row and no token → RED.
examples: B41 (LLR-173.4f) no store file → `("recent", "no recent sources", None)`. `LOCALAPPDATA` unset → the same line (`recent_store_path()` is `None`, no problem). Result `2` of `2`.
examples: B42 (LLR-173.4g) a 65 537-byte store → `("recent", "too large — the next load starts a new list", None)`. The store open raises `PermissionError` (injected) → `("recent", "could not be read — check that the recent-sources file can be opened", None)`. `0` recent rows each (`2` of `2`). Neither line paints any part of the store path (Q5). Negative control: `problem` ignored → `no recent sources` → RED.
examples: B43 (LLR-173.4h) `C:\cal\v2\fw.s19` (kind `s19`) → label `fw.s19 (s19)`, `0` `●`. A 300-character recorded path whose file name is `fw.s19` → the same 12-character label, which fits one line (LLR-173.6n, G-A).
examples: B44 (LLR-173.4j, rows half) a counting spy on `os.stat`, `os.lstat`, `os.scandir`, `os.listdir`, `open`, `os.path.exists`, `Path.exists`, `Path.is_file` and `Path.resolve` while the rows are built over 3 recents (one present, one missing, one on unassigned `Q:`) → `0` calls naming any of the 3 paths.
examples: B45 (LLR-173.4l) one item per section → the rows have section ids `projects, projects, workarea, workarea, recent, recent`, and the headings `Projects`, `Work area` and `Recent` carry `choice None`. Result `6` of `6`. Negative control: a mutation that builds the recent section first → RED.
examples: B46 (LLR-173.4m) `self.workarea.iterdir()` raises `PermissionError` (injected into `list_projects`) → the dialog opens, and the projects section holds `could not be read — check that the folder can be opened, then load again`. The files and recent sections are built as usual, and the app does not raise. Without the catch, the exception leaves `rows()` on mount and the app stops (Textual `exit_on_error`).
examples: B47 (LLR-173.7) the TC-B100-66 scan over the 6 scenarios: every heading, token line and label N1 builds → `0` matches of `\bD\d+\b`, `\bO-\d+`, `VS-`, `LLR-` or `HLR-`.

S19TuiApp._load_dialog_verdict
req: HLR-173d, LLR-173.4k, LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e
in: LoadChoice choice
out: Optional[tuple[str, str]] verdict
func: new; the `verdict` callable (S-b). The dialog calls it on the event loop for every load request with a loadable choice, before it dismisses. It reads metadata only (S-e), paints nothing and writes nothing.
- (1) `choice.kind in ("project", "workarea")` → `None`. No filesystem call: a project pick is refused, if it must be, by `_handle_load_project` with its status line, as on the 9a tree.
- (2) `path` and `recent` → `action, reason = self._typed_load_route(Path(choice.value))`. `action != "refuse"` → `None`; else `_TYPED_REFUSAL_TOKENS[reason]`. A recent goes through the same classifier: an absolute recorded path that is missing → step (1) `not found` → `("not found", "check the path")` (LLR-173.4k; the entry stays, Q3). A data or A2L kind is returned only after the lstat walk shows a regular file (S9b-7); a folder named `x.s19` then takes `("project", name)` when the folder is listed, or the `not a project` refusal when it is not (S9b-7 R2).
- **No `try/except`.** `_typed_load_route` maps every `OSError` itself. A catch here would hide a classifier that leaks, and LLR-173.5e's negative control (the classifier's catch removed) could then not turn RED (R-5, as 9a's R-5).
- The dialog never calls it for blank path text or a heading (S-c, seam V-1). Blank text would classify as `"."`, a folder, which gives `not a supported file`.
callers: `LoadDialog` load request (G-A: `enter`, `alt+l`, `#load_ok`).
module: s19_app/tui/app.py
examples: B48 (LLR-173.5) `LC("path", "<tmp>/missing.s19")` and `LC("path", "<W>/nope")` → `("not found", "check the path")` each. The dialog stays open with the text unchanged; `0` dismisses, `0` status lines. Result `2` of `2`. Negative control (9a tree): `LoadFileScreen` dismisses with the `Path`, and the refusal becomes a status line after the close → RED.
examples: B49 (LLR-173.5a) `<tmp>/notes.txt`, `<tmp>/fw.s19.` (trailing dot, CR9-3) and the relative `.s19tool/workarea/ab` → `("not a supported file", "check the path")` each (`3` of `3`).
examples: B50 (LLR-173.5b) `<W>/temp`, `<W>/TEMP` (Windows only), the empty `<W>/e` and `<W>/ab/flows` → `("not a project", "pick a project in the list")` each, `0` resets (`4` of `4`).
examples: B51 (LLR-173.5c) `<tmp>/P` and `<tmp>/P/project.json` → `("outside the work area", "copy the folder into the work area")` each (`2` of `2`).
examples: B52 (LLR-173.5d, Windows only) `<W>/jx` (a junction to `ab`) and `<W>/jx/project.json` → `("link or junction", "pick a project in the list")` each, `0` resets (`2` of `2`). Not run where no junction can be made.
examples: B53 (LLR-173.5e) `PermissionError` injected into `os.lstat` of the walk prefix `<W>/ab`, and separately `list_projects` raising `PermissionError` → `("could not be read", "check that the folder can be opened, then load again")` each, `0` raises (`2` of `2`). Negative control: the classifier's `except OSError` at step (6) removed → the `PermissionError` leaves `verdict()` inside the dialog's key handler → the app stops → RED.
examples: B54 (LLR-173.4k) a recent whose file was deleted after it was recorded, then `enter` → `("not found", "check the path")`, `0` dismisses, `0` loads, the store's SHA-256 unchanged (`1` of `1`). Negative control: a verdict that returns `None` for `recent` → the dialog closes and the router paints the status line → RED.
examples: B55 (go arms) `LC("path", "<tmp>/a.s19")` → `None`. `LC("project", "ab")` → `None`, with `0` calls of `os.lstat` or `list_projects` (spy). `LC("workarea", "x.s19")` → `None`. `LC("recent", "C:\s\fw.s19")`, present → `None`. Result `4` of `4`.
examples: B97 (S9b-7 R2) `LC("path", "<W>/ab.s19")` where `ab.s19` is a folder: listed (holds a data, MAC or A2L file, or a regular `project.json`) → `("project", "ab.s19")`; unlisted and empty → `("refuse", "not a project")` → the verdict paints `not a project` / `pick a project in the list`. `0` dismisses, `0` loads. The `not found` sentence is dropped.
examples: B56 (HLR-173d) the empty Load (G-A) plus the 6 reasons B48–B53 → `7` token pairs in `#load_reason`, `0` dismisses, the field text unchanged (`7` of `7`).
examples: B57 (table census, unit) every `("refuse", <literal>)` that `_typed_load_route` returns (AST) → 6 reason words, all keys of `_TYPED_REFUSAL_TOKENS` (`6` of `6`). A future reason with no key raises `KeyError` here, and this census turns RED first.

S19TuiApp._load_dialog_preview
req: LLR-173.4i, LLR-173.4j, LLR-173.3c, LLR-173.6, LLR-173.6b, LLR-173.6d, LLR-173.6f, LLR-173.6k, HLR-173a
in: LoadChoice choice
out: list[PreviewLine] lines
func: new; the `preview` callable (S-b). It returns the lines; the dialog paints them (A9b-04: synchronous, no `deliver`, no generation). It dispatches on `choice.kind`:
- `recent` → **synchronous** `[(pn_full(v), False), (f"kind {recent_kind(Path(v))}", False), ("checked when loaded", False)]`. Here `pn_full(v) = painted_names([v], clip=len(v))`: the full path, with no 120-character clip (LLR-173.4i "full recorded path"); the entry check already refused Cc, Cf, Zl, Zp and Cs. `recent_kind` is pure (`PureWindowsPath`). There is `0` filesystem calls and `0` marks.
- `workarea` → **synchronous** `self._file_preview_marks(self.workarea / WORKAREA_TEMP / v)`, with no filesystem call.
- `path` → no preview: `[]` (A9b-07 removed the typed-file arm; the dialog never asks while the field is the source).
- `project` → **synchronous** build (Q2: every step reads only metadata and the bounded `project.json`; no `check_project_files`, no thread). `folder = self.workarea / v`; inside `try … except OSError:` → `[("could not be read — check that the folder can be opened, then load again", False)]` (LLR-173.6k). Otherwise: `data_files, a2l_files = self._list_project_files(folder)` (R2-N2: link-safe, no linked child's target is followed, LLR-173.4n); before any manifest read, the lstat regular-file gate on `project.json` (S9b-2): if it is not a regular file (a FIFO, a link, a directory), paint `could not be read`, set `recorded = None` and do not open it (R2-N5); a regular file → `manifest = read_project_manifest(folder)`; `variant_set = build_variant_set(v, data_files)`; `recorded = manifest.active_variant if manifest is not None and not manifest_is_damaged(manifest) else None`; `a2l_ok = bool(a2l_files) and self._a2l_admission(a2l_files[0]) is None`; `install_a2l = a2l_files[0] if a2l_ok else None` (A9b-R2-6: the one A2L admission, shared with the install); `install = choose_install_set(variant_set, recorded, data_files, install_a2l)`; when the scan finds more than one MAC or more than one A2L, every mark is `False` and no extra line is painted (A9b-R2-3 / R2-N1: the install refuses, so `0` `●` already says nothing installs); then `lines` is, in order: each variant `(f"variant {pn(v.path.name)}", v.variant_id == install.variant.variant_id)`; each MAC `(f"MAC {pn(p.name)}", p == install.mac)`; the A2L `(f"A2L {pn(a2l_files[0].name)}", a2l_ok and install.a2l is not None)`; `(f"project file: {state}", False)`. There is no sub-folder line (S9b-3 removed LLR-173.6e).
callers: `LoadDialog` (G-A): on a highlight, never on a path-field edit (A9b-07), with no rest timer (Q2 removed LLR-173.6j).
module: s19_app/tui/app.py
examples: B58 (LLR-173.4i) recents `C:\cal\v2\fw.s19`, `C:\cal\c.a2l` and `C:\cal\m.mac`, highlighted in turn → 3 synchronous returns. The first is `[("C:\cal\v2\fw.s19", False), ("kind s19", False), ("checked when loaded", False)]`, which paints as `C:\cal\v2\fw.s19` / `kind s19` / `checked when loaded`. Each result has `0` marked lines (`3` of `3`). A 300-character recorded path → the first line holds all 300 characters. Negative control (code read, `1d677ba` `pa_C.preview_file` reads the bytes) → a copy previews size and "same bytes" → RED.
examples: B59 (LLR-173.4j, preview half) the counting spy of B44 while the 3 recents (present, missing, `Q:`) are highlighted and previewed → `0` calls naming any of them. Negative control: a mutation that adds `os.path.getsize(v)` to the recent preview → `1` call per highlight → RED.
examples: B60 (LLR-173.3c, recent) `C:\x\[bold]a.s19` → the first line is `C:\x\[bold]a.s19` as literal text, with `0` spans (G-A paints it with markup off).
examples: B61 (A9b-07) `LC("path", "<tmp>/a.s19")` → `[]`; `LC("path", "<tmp>/notes.txt")` → `[]`; `LC("path", "   ")` → `[]`; `LC("path", "<W>/ab")` → `[]`. There is no typed-file preview: the dialog never asks while the field is the source (`0` filesystem calls each).
examples: B62 (synchronous project dispatch, Q2) `LC("project", "ab")` → `preview()` builds the lines and returns them before it returns; `0` threads start, `0` calls of `check_project_files` (spy).
examples: B64 (LLR-173.6, HLR-173a; each project highlighted, then `enter` → the Loaded panel compared). Clean project `ab` (`a.s19`, `m.mac`, `c.a2l`, `project.json` with `active_variant` `a` and all digests matching) → `● variant a.s19`, `● MAC m.mac`, `● A2L c.a2l`, `project file: ok` → the panel names image `a.s19`, MAC `m.mac`, A2L `c.a2l`.
examples: B65 (LLR-173.6, save-back) project `sb` with `a.s19` and `b.s19`, and `active_variant` `b` after a save-back → `variant a.s19`, `● variant b.s19`, `project file: ok` → panel image `b.s19`. Negative control: a mutation that marks the first variant by name → `● variant a.s19` ≠ panel `b.s19` → RED.
examples: B66 (LLR-173.6, recorded active missing) project `rm` with `a.s19` and `c.hex`, and `active_variant` `zz` → `● variant a.s19`, `variant c.hex` → panel image `a.s19`.
examples: B67 (LLR-173.6, A2L-only) project `ao` with `c.a2l` and `project.json` → `● A2L c.a2l`, `project file: ok` → panel: image absent, MAC absent, A2L `c.a2l`. The four arms B64–B67 give `4` of `4`.
examples: B68 (LLR-173.6a) project `z0` whose recorded active `b.s19` is a 0-byte file beside `a.s19` → `● variant b.s19`, because no image is read before `enter`. After `enter`, the Load-result panel opens `a.s19` and names `b.s19` `not readable` (`2` of `2`). Declared: this holds on the 9a tree for the panel (Inc 7), and the RED is a mutation that drops the reason line.
examples: B69 (LLR-173.6d) variants `b.s19`, `a.s19` and `c.hex` → 3 variant lines, `variant a.s19`, `variant b.s19`, `variant c.hex`, in `build_variant_set` order `(name.lower(), name)`. Exactly one carries `●` (`1` of `1`). Negative control: only the marked variant listed → `1` line → RED.
examples: B71 (LLR-173.6f) a valid manifest → `project file: ok`. None → `project file: no project.json`. A manifest of 1 048 577 bytes → `project file: manifest damaged`. Result `3` of `3`. Negative control: `ok` whenever the file exists → the over-cap arm paints `ok` → RED.
examples: B73 (LLR-173.6k) `PermissionError` injected into `app_module._list_project_files` (the folder listing, R2-N4), and separately into `app_module.read_project_manifest` → `[("could not be read — check that the folder can be opened, then load again", False)]` each. `0` `●`, `0` raises, the dialog open (`2` of `2`). F-5: an injection into `open()` of `project.json` does not reach this catch; it gives `project file: manifest damaged`. Negative control: the catch removed → the builder raises → `exit_on_error` stops the app → RED.
examples: B76 (LLR-173.3c, project) project `P` holding `[b]v.s19`, `[i]m.mac` and `[u]c.a2l` → lines `● variant [b]v.s19`, `● MAC [i]m.mac`, `● A2L [u]c.a2l`, all literal, with `0` spans from them (`3` of `4`; the 4th is B60).
examples: B77 (HLR-173a, A2L left out) project `big` with `a.s19` and an A2L of `DEFAULT_COPY_SIZE_CAP_BYTES + 1` bytes (the cap lowered by `monkeypatch.setattr(workspace, "DEFAULT_COPY_SIZE_CAP_BYTES", …)`, which is read at call time on both sides) → `● variant a.s19`, `A2L big.a2l` unmarked. After `enter`, the panel shows image `a.s19`, A2L absent, and the problem `not readable` on `big.a2l`.
examples: B78 (A9b-R2-3, R2-N1) project `mm` with `a.s19`, `m1.mac` and `m2.mac` → the scan finds more than one MAC → every mark is `False` (`0` `●`), no `cannot load:` line is painted; after `enter` nothing is installed and the Load-result panel names the problem (HLR-178).
examples: B98 (S9b-2, R2-N5) project `P` whose `project.json` is a FIFO (or a symlink to one, or to `\\host\share\…`) → the preview paints `could not be read`, sets `recorded = None` and makes `0` `open` calls on it, `0` raises. A linked `project.json` is not opened on a highlight.

S19TuiApp._file_preview_marks
req: LLR-173.6b, LLR-173.6c, LLR-173.3c, HLR-173a
in: Path path
out: list[PreviewLine] lines
func: new; pure over session state and the file name, run on the event loop with no filesystem call. It encodes the install rule the E1 "live semantics" note asked E2 to state:
- `_parse_loaded_file` attaches `a2l_files[0] if a2l_files else self.current_a2l_path` (:15150);
- `_merge_primary_with_existing_mac` keeps the session MAC under a new S19/HEX image (:14393-14410);
- `_merge_mac_with_existing_primary` keeps the image under a new MAC (:14447-14465);
- `load_a2l_from_path` keeps image and MAC;
- the Loaded panel names `current_file.path` / `.mac_path` / `.a2l_path`, or `current_a2l_path` when there is no image (`screens_directionb.py` `_slot_state`).
Let `cur = self.current_file` and `kept_a2l = self.current_a2l_path or (cur.a2l_path if cur else None)`. Then, by suffix:
- S19/HEX (`PROJECT_PRIMARY_DATA_EXTENSIONS`):
  - `(f"image {pn(path.name)}", True)`;
  - if `cur` and `cur.mac_path` → `(f"MAC {pn(cur.mac_path.name)}", True)`;
  - if `kept_a2l` → `(f"A2L {pn(kept_a2l.name)}", True)`;
  - if `self.current_project` → `(f"becomes the active variant of project {pn(self.current_project)}", False)` (LLR-173.6c).
- MAC:
  - if `cur` and `cur.file_type in {"s19", "hex"}` → `(f"image {pn(cur.path.name)}", True)`;
  - `(f"MAC {pn(path.name)}", True)`;
  - if `kept_a2l` → the A2L line. No project note: a MAC is an overlay, not a variant (declared).
- A2L:
  - if `cur` and `cur.file_type in {"s19", "hex"}` → the image line;
  - if `cur` and `cur.mac_path` → the MAC line;
  - `(f"A2L {pn(path.name)}", True)`. No note.
callers: `_load_dialog_preview` (`workarea` kind).
module: s19_app/tui/app.py
examples: B80 (LLR-173.6b arm 1) nothing loaded, row `a.s19` → `● image a.s19` (`1` `●`). After `enter`, the panel image is `a.s19`, and MAC and A2L are absent.
examples: B81 (arm 2) `cal.a2l` loaded alone, row `a.s19` → `● image a.s19`, `● A2L cal.a2l` (`2` `●`) → the panel shows image `a.s19` and A2L `cal.a2l`.
examples: B82 (arm 3, the E1 live-semantics row) `f.s19` and `m.mac` loaded, row `b.hex` → `● image b.hex`, `● MAC m.mac` (the merge keeps the MAC) → the panel shows image `b.hex` and MAC `m.mac`.
examples: B83 (arm 4) `f.s19` loaded, row `c.a2l` → `● image f.s19`, `● A2L c.a2l` → the panel shows image `f.s19` and A2L `c.a2l`. B80–B83 give `4` of `4`. Negative control: a mutation that marks only the highlighted file → the B81 arm has `1` `●` against 2 panel slots → RED.
examples: B84 (LLR-173.6c) project `P` open, row `a.s19` → the line `becomes the active variant of project P` (unmarked, painted literally). No project open → `0` note lines. `P` open, row `c.a2l` → `0` notes. Result `3` of `3`. Also `P` open, row `m.mac` → `0` notes (declared). Negative control: the note painted whatever the state → the no-project arm RED.
examples: B86 (LLR-173.3c) a work-area row `[b]v.s19` with `[i]m.mac` loaded → `● image [b]v.s19`, `● MAC [i]m.mac`, literal.

S19TuiApp._load_workarea_file
req: LLR-173.1b, LLR-173.3d
in: str name
out: None
func: new (G1); `_load_from_item`'s body verbatim (A9b-05 reverses B-2): `candidate = self.workarea / WORKAREA_TEMP / name`; if `candidate.exists()`, log `Loading from workarea selection: %s`, then for an A2L suffix call `load_a2l_from_path(candidate)` (the 9a route, including `copy_into_workarea` — an identical-file reuse that keeps the 256 MB cap and the link re-check), else `load_selected_file(candidate)`. The `0`-copy rule (LLR-173.1b) covers the data arm only. The name is the on-disk name (S3 of 9a; `LoadChoice.value`).
callers: `_load_from_item` (the `#files_list` pick); `_handle_load_dialog` (`workarea` kind).
module: s19_app/tui/app.py
examples: B87 (LLR-173.1b twin) twin fixtures, each with `W/temp/x.s19` → a `#files_list` pick of `x.s19` on one, and `LC("workarea", "x.s19")` through the router on the other → equal session digests, and `0` `copy_into_workarea` calls on both.
examples: B88 (pre-existing, declared, F-11) `W/temp/x.s19` deleted after the dialog opened, then `enter` on its row → the verdict is `None` → `candidate.exists()` is false → `0` loads and `0` status lines (silent, as the 9a list pick already is).

S19TuiApp._load_from_item
req: LLR-172.6a
in: ListItem item
out: None
func: changed (G1): `filename = getattr(item, "data", None)`; `if not filename: return`; `self._load_workarea_file(filename)`. Behaviour is unchanged: an A2L pick goes through `load_a2l_from_path` as on 9a (A9b-05).
callers: `on_list_view_selected` (`#files_list`).
module: s19_app/tui/app.py
examples: B89 (holds on the 9a tree) LLR-172.6a pick arms (9a B-examples `refresh_files`): `item.data` is the on-disk name, and `current_file.path.name` equals it (`4` of `4`). `item.data is None` → `0` calls.

S19TuiApp.check_action
req: LLR-173.2e
in: str action, tuple parameters
out: Optional[bool]
func: changed (G3), with a new first test: `if action in _LOAD_DIALOG_INERT_ACTIONS and any(isinstance(s, LoadDialog) for s in self.screen_stack): return False`. The constant `_LOAD_DIALOG_INERT_ACTIONS = frozenset({"load_file", "save_project", "focus_palette", "cycle_density"})` holds the action names of the four `priority=True` bindings (`BINDINGS` :2120-2123; S-g confirmed: the density action is `cycle_density`). The whole-stack guard (S9b-1) keeps the four keys inert even when the command palette or another modal sits over the dialog. The name test runs first, so `self.screen_stack` is read only for those four actions. Then the existing window gates and `super().check_action`.
callers: Textual `App.run_action` (`textual/app.py:4245`), for every key binding and palette dispatch.
module: s19_app/tui/app.py
examples: B90 (LLR-173.2e, S9b-1) with the dialog open, press `ctrl+l` → stack depth `2`, `0` second dialog. `ctrl+s` → depth `2`, `0` `SaveProjectScreen`. `ctrl+k` → the focus stays inside the dialog and the palette input is not focused. `ctrl+d` → `self.density` unchanged. `ctrl+p` over the dialog (the command palette opens over it), then `ctrl+s` → `0` Save pushes, and then `ctrl+l` → `0` second dialogs (the guard reads the whole stack). Result `6` of `6`. Negative control (code read, Textual 8.2.8 `_check_bindings(priority=True)` walks `reversed(self.screen._binding_chain)`, App included, `textual/app.py:3978-3987`): on the 9a tree `ctrl+l` pushes a second Load dialog → RED; the executed S9b-1 probe shows the old stack-top guard gives `['Screen','Dlg','CommandPalette','Save']` after `ctrl+p` then `ctrl+s` → RED.
examples: B91 (no over-reach) with the dialog closed, `ctrl+l` opens it (`1`), and `ctrl+d` cycles the density (`1`).
examples: B92 (F-4, declared) the focus is on `#load_path` holding `abc` with the cursor at 0. `ctrl+d` → `check_action` false → `_check_bindings` goes on to the non-priority chain → `Input` binds `delete,ctrl+d` to `delete_right` (`textual/widgets/_input.py:120`) → the text becomes `bc`. `ctrl+k` → `delete_right_all` (`:137`) → the text becomes empty. No app action runs, so LLR-173.2e holds; the field edit is a UX note for E3.

S19TuiApp._handle_load_project
req: LLR-173.1g, LLR-173.4a, LLR-172.5g
in: Optional[str] name
out: None
func: changed (F-12, S9b-2, S9b-5, R2-N2, A9b-R2-6); the lstat regular-file gate on `project.json` runs before any manifest read (S9b-2): a `project.json` that is not a regular file (a FIFO, a link) → `1` status line `could not be read`, `0` opens, and the file is not opened. The file listing is `self._list_project_files(project_dir)` (R2-N2), in place of `validate_project_files`, so linked children are neither listed nor installed (LLR-173.4n); the same cardinality rule (more than one MAC or more than one A2L → refuse) and the A2L admission (`self._a2l_admission`, A9b-R2-6) are shared with the preview, so the marks equal the install. One new `try/except OSError` around `self._list_project_files(project_dir)` at :11743. The catch paints `1` status line with `could not be read` (`Project NOT loaded: '<name>' could not be read — check that the folder can be opened, then load again.`, the same wording as the :11716-11721 arm), logs a warning, and returns — the session is unchanged and nothing crashes. The `Project not found: {name}` status line paints the name through `painted_names` (S9b-5), the same scrub as the dialog. Every other line is the 9a body unchanged.
callers: `_route_load_project` (:7478, via `_handle_load_dialog`); direct test callers (`test_b100_project_homes.py`, `test_tui_app.py`).
module: s19_app/tui/app.py
examples: B96 (LLR-173.1g) a project listed fail-open (`held is None`), then `enter` → `_list_project_files` raises `PermissionError` (injected) → `1` status line holding `could not be read`, `0` raises, the session digest unchanged. Negative control: the catch removed → the `OSError` leaves the dismiss callback and the app stops → RED.
examples: B99 (S9b-2) a listed project whose `project.json` is a FIFO (or a symlink to one) → `enter` → the lstat gate refuses it: `1` status line `could not be read`, `0` `open` calls on the link's target, `0` raises, the session unchanged.
examples: B100 (S9b-5) a project renamed between dialog open and `enter`, named `x` + U+202E + `R` → the `Project not found:` status line paints the scrubbed name (U+202E removed through `painted_names`), not the raw on-disk name.

Module constants (data)
req: LLR-173.4g, LLR-173.5, LLR-173.5a, LLR-173.5b, LLR-173.5c, LLR-173.5d, LLR-173.5e, LLR-173.2e, LLR-173.7
in:
out:
func: new, module level in `app.py`.
- `_TYPED_REFUSAL_TOKENS: dict[str, tuple[str, str]]` (G2):
  - `"not found"` → `("not found", "check the path")`;
  - `"not a supported file"` → `("not a supported file", "check the path")`;
  - `"not a project"` → `("not a project", "pick a project in the list")`;
  - `"outside"` → `("outside the work area", "copy the folder into the work area")`;
  - `"link"` → `("link or junction", "pick a project in the list")`;
  - `"unreadable"` → `("could not be read", "check that the folder can be opened, then load again")`.
  - These are the §3 token rows (D.2), exactly.
- `_RECENT_PROBLEM_STEPS: dict[str, str]` (Q5):
  - `RECENT_PROBLEM_TOO_LARGE` → `"the next load starts a new list"`;
  - `RECENT_PROBLEM_UNREADABLE` → `"check that the recent-sources file can be opened"`.
- `_LOAD_DIALOG_INERT_ACTIONS` (G3, above).
module: s19_app/tui/app.py
examples: B93 (LLR-173.7) the TC-B100-66 scan of the refusal-token constants → `0` matches of the decision-id patterns.
examples: B94 (§3 table equality, unit) each pair in `_TYPED_REFUSAL_TOKENS` and `_RECENT_PROBLEM_STEPS` equals a row of the §3 token table after the D.2 merge (`8` of `8`).

## Context nodes (unchanged)

S19TuiApp._route_load_project — unchanged (:7449). New caller: `_handle_load_dialog` (`project`); its old caller `LoadProjectScreen`'s callback retires (Q9). B07 is its example.

S19TuiApp._load_path_from_user_input — unchanged (:12905). New caller: `_handle_load_dialog` (`path`, `recent`), with the same deferred call as on the 9a tree. Example B95 (E1 §5 observation, accepted): a typed `<tmp>/a.s19` passes the verdict, and the file is deleted before the deferred route runs → `1` status line `File NOT loaded: '<tmp>\a.s19' not found — check the path.` after the dialog has closed.

choose_install_set — unchanged (:1593). New caller: `_load_dialog_preview` (project branch), with `unreadable=()`. Examples B64–B68.

## Entities

[I/O: recent-sources store]
desc: unchanged owner (G1 of 9a). 9b reads it once per dialog open (`read_recent_sources` in N1) and makes no write beyond the 9a record, which LLR-172.1n now narrows.
sequence:
  dialogOpen: LoadDialog.on_mount → S19TuiApp._load_dialog_rows → read_recent_sources → expect rows (0 calls on entry paths)
  recentPick: LoadDialog load → S19TuiApp._load_dialog_verdict → S19TuiApp._typed_load_route (abs) → None → S19TuiApp._handle_load_dialog → S19TuiApp._load_path_from_user_input → S19TuiApp.load_from_path → record_recent_source (moves to first)
  recentMissing: S19TuiApp._load_dialog_verdict → S19TuiApp._typed_load_route (refuse "not found") → expect none (dialog open, store bytes unchanged)
  fallbackSource: S19TuiApp.load_from_path → copy_into_workarea wins → via_fallback (True) → expect none (0 record calls)

[I/O: workarea temp]
desc: enumerated only by `list_workarea_files`; the dialog's files section filters its result by `recent_kind`.
sequence:
  dialogRows: S19TuiApp._load_dialog_rows → list_workarea_files → recent_kind filter → rows (value = on-disk name)
  dialogPick: S19TuiApp._handle_load_dialog (workarea) → S19TuiApp._load_workarea_file → S19TuiApp.load_selected_file / S19TuiApp.load_a2l_from_path (the 9a route, A9b-05)

[state: project preview]
desc: the project preview is built synchronously on the event loop (Q2): metadata and the bounded `project.json` only, so there is no worker thread and no hashing on a highlight.
sequence:
  projectPreview: LoadDialog (highlight) → S19TuiApp._load_dialog_preview → build (`_list_project_files` link-safe scan → `_a2l_admission` → project.json lstat gate → read_project_manifest → manifest_is_damaged → build_variant_set → choose_install_set) → returns lines → LoadDialog.show_preview (paints)
  previewError: S19TuiApp._load_dialog_preview (OSError) → expect token line (0 ●, 0 raises)

## Callers and what changes for each

| Caller (line) | Reaches | What changes for it |
|---|---|---|
| `ctrl+l`, `l`, palette `load_file` | `action_load_file` | Opens the new dialog on `#load_path`. `ctrl+l` is inert while the dialog is open (G3). |
| `p`, `#ws_load_project_button` (:17632), palette `load_project` | `action_load_project` | Opens the same dialog on `#load_list`, also with 0 projects; `No saved projects found.` goes (B07a re-pin). |
| `LoadDialog` dismiss | `_handle_load_dialog` | One router for 4 kinds plus `None`; `_route_load_project` is no longer a dismiss callback. |
| `tests/test_tui_app.py:1254`, `:1288`; `tests/test_b100_active_variant.py:210` | `_handle_load_dialog` | Re-pinned to `LoadChoice("path", str(p))` (A9b-08). |
| `on_list_view_selected` (`#files_list`) | `_load_from_item` → `_load_workarea_file` | Same behaviour (B89). |
| `_typed_load_route` step 9, `_handle_load_project` (:11714) | `list_projects` | No longer see folders without project content. An empty folder passed by name is refused `not a project` (RC-1, B21). |
| `_load_path_from_user_input`, `_handle_select_variant` (:7606) | `load_from_path` | A source found only through the fallback is no longer recorded; every other path is unchanged (inside sources were never recorded). |
| `_load_path_from_user_input` | `load_a2l_from_path` | Same condition (B30). `_load_workarea_file` reaches it again for the A2L arm (A9b-05). |
| Textual `run_action` | `check_action` | False for 4 actions while `LoadDialog` is the screen. |
| 3 tests of empty folders (B20); `test_b99_load_project.py:335` (B07a); TC-B100-32 empty arm (B21) | — | Re-pin; the last needs the RC-1 ruling first. |

## Seams with G-A (`screens.py`, `styles.tcss`)

| Id | Seam | G-B side (this design) | G-A must | Example |
|---|---|---|---|---|
| S-a | `LoadChoice` | G-B builds `project` / `workarea` / `recent` choices in N1, with `value` = the on-disk name or the recorded path text; the router reads `kind` / `value` only | build `LC("path", text)` with the field text verbatim (no strip; the route strips) | B31, B36, B11 |
| S-b | `LoadDialog.__init__` | `mode` `"path"` (A2) / `"list"` (A3); `highlight=self.current_project` in both; the 3 bound methods | — | B01, B03, B04 |
| S-c | rows | section ids `"projects"`, `"workarea"`, `"recent"`; each section starts with its heading row; labels are already scrubbed, plain `str` | paint every label with markup off (`Text(label)` or `Content`, never markup); disable every `choice None` row; no re-scrub | B31–B35, B45 |
| S-d | preview lines | plain `str`; `marked` per line | prefix `● ` only where marked; markup off; preview lines nowrap with ellipsis (S9b-8) | B58, B64, B76 |
| S-e | preview | every kind returns the lines synchronously, inside the `preview()` call (A9b-04); no `deliver`, no generation | paint what `preview()` returns; no stale check | B58, B62 |
| V-1 | verdict calls | handles `path`, `recent`, `project`, `workarea`; no blank-text arm | never call `verdict` for blank path text (paint `nothing selected` / `pick a row or type a path` itself, LLR-173.2h) or for a `choice None` row (LLR-173.2i) | B48–B56 |
| S-f | precedence | — (G-A only) | as fixed | B15 |
| S-g | priority keys | `check_action` names `load_file`, `save_project`, `focus_palette`, `cycle_density`; the guard reads the whole stack `any(isinstance(s, LoadDialog) for s in self.screen_stack)` (S9b-1) | — | B90–B92 |
| H-1 | highlight | passes the on-disk project name or `None` | highlight the row whose choice is `LC("project", highlight)`; none → the first project row; 0 projects → the first loadable row | B05, B06 |
| I-1 | imports (LLR-173.6l) | `app.py` imports `LoadChoice`, `LoadDialog` | `screens.py` gains 0 imported modules | B03 |

No **proposed interface change.** V-1 and H-1 are clarifications that use only the fixed signatures; they are written here for the orchestrator to confirm in `interfaces-9b.md`.

## Findings

finding F-1 (RC-1, requirement conflict) LLR-171.2e becomes unreachable through `_handle_load_project`
anchor: S19TuiApp.list_projects
seen: LLR-171.2e (Inc 8b) asks that an empty folder passed by name to the project load be refused with `no project.json` (TC-B100-32, `tests/test_b100_project_homes.py:1022-1046`). With Q7 the empty folder is not listed. 9a's listing step (LLR-172.5g, `_handle_load_project` :11713-11740) runs before `validate_project_files` and refuses it with `not a project` / `pick a project in the list`.
cause: Q7 (§1.3 in `list_projects`) combined with 9a's R3 listing match.
effect: the TC-B100-32 empty-folder arm turns RED. No UI path reaches the 8b text any more: the dialog does not list the folder, and the typed route refuses it at step 9.
decision: **ruled (E2 F-1):** LLR-171.2e is retired, superseded by LLR-173.4a (Q7) — an empty folder is no longer a listed project. The TC-B100-32 `[no project.json]` arm and the 4 other census tests are re-pinned (test notes in E1-scope.md). LLR-171.2d is unaffected, because a folder holding only `project.json` is listed.

finding F-2 (requirement gap) an unreadable project list has no requirement in the dialog
anchor: S19TuiApp._load_dialog_rows
seen: `list_projects` raises `OSError` when `W` cannot be listed (`iterdir`, as on the 9a tree). No LLR-173.4* covers it, and uncaught it stops the app on dialog mount.
decision: designed (B46) with the existing `could not be read` row. **Accepted LLR-173.4m (unwanted, E2-rulings F-2):** "If the project list cannot be read, then the system shall paint `could not be read` and `check that the folder can be opened, then load again` in the Load dialog's projects section." Threshold: `PermissionError` injected into `list_projects` → 1 line, the dialog open, 0 raises. Negative control: no catch → the app stops.

finding F-3 (deviation from E1 "unchanged context") §1.3 would exist twice
anchor: S19TuiApp._folder_holds_project
seen: putting the §1.3 test in `list_projects` (Q7) would duplicate `_typed_load_route` step 11 (:12885-12903).
decision: lift step 11 into `_folder_holds_project` (`Optional[bool]`) and use it in both places, so there is one definition (Q7's own words). `_typed_load_route` therefore changes in step 11 only, with identical returns (B23). An unreadable folder is listed, not skipped: skipping would turn 9a's TC-B100-38 arm "route: validate_project_files" from `unreadable` into `not a project`.

finding F-4 `Input`'s own `ctrl+d` / `ctrl+k` still edit `#load_path`
anchor: S19TuiApp.check_action
seen: `textual/widgets/_input.py:120` (`delete,ctrl+d`) and `:137` (`ctrl+k`); `run_action` returns False for a check-refused action, and `_check_bindings` continues (`textual/app.py:3984-3988`, `:4245-4248`).
effect: LLR-173.2e (no app action) holds, but `ctrl+k` clears the typed text to the right of the cursor.
decision: declared (B92). E3 or UX may ask G-A to bind both keys to no-ops in the dialog. That would need no G-B change.

finding F-5 LLR-173.6k's manifest arm needs the right injection point
anchor: S19TuiApp._load_dialog_preview
seen: `read_project_manifest` catches `OSError` from its own `open` and returns a damaged manifest (`variant_execution_service.py:1525-1540`). Only its `exists()` (:1497) or a patched function raises.
decision: a test note for E4: inject into `app_module.read_project_manifest` (or `Path.exists`), not into `open`. No source change.

finding F-6 LLR-172.1n's threshold has no A2L arm
anchor: S19TuiApp.load_a2l_from_path
decision: B30 is designed. Proposed: add it to TC-B100-34 as a 5th arm (`5` of `5`).

finding F-7 the typed-path preview is removed (A9b-07)
anchor: S19TuiApp._load_dialog_preview
seen: LLR-173.6b marked a typed file "the typed-path route accepts". That would require a filesystem touch before Enter (which S-07 forbids) or a suffix-only mark that disagrees with the install.
decision: **ruled (A9b-07):** the typed-file arm of LLR-173.6b and HLR-173a is retired, and `on_input_changed` is deleted. The preview shows no lines while the path field is the source.

finding F-9 an A2L row while the open project already has an A2L
anchor: S19TuiApp._file_preview_marks
seen: `load_a2l_from_path` refuses with `Project already has an A2L file.` (:13106-13109); the preview marks the A2L.
decision: E3 to rule. Deciding it needs `validate_project_files(project_dir)` on the event loop at each highlight. Not designed (not asked).

finding F-10 an install-time A2L parse failure cannot be previewed
anchor: S19TuiApp._load_dialog_preview
decision: declared, as LLR-173.6a declares it for variants: the panel names the problem. The metadata part (link, size cap) is mirrored (B77).

finding F-11 a work-area file deleted between open and `enter` loads nothing, silently
anchor: S19TuiApp._load_workarea_file
decision: this is the 9a list pick's behaviour, kept (B88). It could be a `workarea` verdict arm (`exists()`, then `not found` / `check the path`), but none is asked. E3 to rule.

finding F-12 (MAJOR candidate, pre-existing) picking an unreadable project folder raises
anchor: S19TuiApp._handle_load_project
seen: `validate_project_files(project_dir)` at :11743 is not wrapped. A folder listed with `held is None` (fail-open, F-3) can be picked. On the 9a tree the old dialog listed such folders too.
effect: an `OSError` leaves the dismiss callback, and the app stops.
decision: designed (B96, E2-rulings F-12): the unwanted LLR-173.1g plus a catch at :11743 that paints the existing `could not be read` row (the same text as :11716-11721). This is about 6 lines in `app.py`.

finding F-15 a project whose files break the cardinality rule
anchor: S19TuiApp._load_dialog_preview
decision: **removed (A9b-16):** the `cannot load: <validate error>` line is dropped; `0` `●` already says nothing installs. The Loaded panel after Enter still names the problem (HLR-178).

## Design risks

- **R-1 (UI-thread cost).** `list_projects` now lists each project folder that has no `project.json`, at dialog open, per typed project path and per project load. Estimated under 20 ms for 50 local folders (not measured); a network work area costs more. E4 logs the time once.
- **R-4 (two classifications).** The verdict and the deferred route both classify a typed or recent path (B95). This is accepted, as in E1 §5.
- **R-5 (no catch in the verdict).** By design, so that LLR-173.5e's classifier-catch mutant stays RED. A leak in `_typed_load_route` would stop the app from inside the dialog. B53 and B57 are the guards.
- **R-6 (R2-N3b).** The `project.json` lstat regular-file gate runs before `read_project_manifest`, which repeats `exists` / `stat` / `open`. A local attacker swapping the file inside that window could open a link's target. Accepted: no change in 9b.

## Windows-only arms (reported not run on the Linux CI, never passed)

B08 (case), B18 / B52 (junctions), B24 / B27 (junction fallback), B33 (U+009B name), B34 (surrogate name), B50 (`TEMP`).

## Requirement coverage (G-B)

| Requirement | Examples |
|---|---|
| HLR-173 | B01, B31, B32 |
| HLR-173a | B64–B68, B77, B78, B80–B84, B86, B101, B103 |
| HLR-173b | B13, B16, B54 |
| HLR-173c | B11, B15 |
| HLR-173d | B48–B53, B56 |
| HLR-173e | B14 |
| LLR-173.1 (router half) | B07, B09, B11, B13, B14 |
| LLR-173.1a | B07, B08 |
| LLR-173.1b | B09, B10, B87 |
| LLR-173.1c | B11 |
| LLR-173.1e | B02 |
| LLR-173.1f | B13 |
| LLR-173.1g | B96, B99 |
| LLR-173.2 | B01 |
| LLR-173.2a | B04, B07a |
| LLR-173.2b | B05, B06 |
| LLR-173.2e | B90, B91, B92 |
| LLR-173.2f / LLR-173.2g (router half) | B15 |
| LLR-173.2k / LLR-173.2l | B14 |
| LLR-173.3 | B33 |
| LLR-173.3a | B34 |
| LLR-173.3b | B35 |
| LLR-173.3c | B60, B76, B86 |
| LLR-173.3d | B32, B36 |
| LLR-173.4 | B18, B31 |
| LLR-173.4a | B17, B20, B22 |
| LLR-173.4b | B37 |
| LLR-173.4c | B38 |
| LLR-173.4d | B39 |
| LLR-173.4e | B40 |
| LLR-173.4f | B41 |
| LLR-173.4g | B42 |
| LLR-173.4h | B43 |
| LLR-173.4i | B58 |
| LLR-173.4j | B44, B59 |
| LLR-173.4k | B54 |
| LLR-173.4l (rows half) | B45 |
| LLR-173.4m | B46 |
| LLR-173.4n | B101 |
| LLR-173.5 | B48, B97 |
| LLR-173.5a | B49 |
| LLR-173.5b | B50 |
| LLR-173.5c | B51 |
| LLR-173.5d | B52 |
| LLR-173.5e | B53 |
| LLR-173.6 | B64–B67, B78 |
| LLR-173.6a | B68 |
| LLR-173.6b | B80–B83 |
| LLR-173.6c | B84 |
| LLR-173.6d | B69 |
| LLR-173.6f | B71, B98 |
| LLR-173.6k | B73 |
| LLR-173.6l (callables half) | B03 |
| LLR-173.7 | B47, B93 |
| LLR-172.1n | B24–B29, B30 |
| LLR-172.4 (census widened) | B37 |
| LLR-166.1 (9b arm) | B14 |
| LLR-178.3 | B07 |
| AT-B100-14 (G-B half) | B16 |

**G-A only** (no G-B node; listed so nothing is lost): LLR-173.2c, LLR-173.2d, LLR-173.2h, LLR-173.2i, LLR-173.2j, LLR-173.6m, LLR-173.6n, and the G-A halves of LLR-173.1, LLR-173.2f, LLR-173.2g, LLR-173.4l and LLR-173.6l. LLR-173.2m was removed by Q8.

**G-B requirements left uncovered: none.**
