# Code-Wire prototype — Inc 9a, group G2 (`s19_app/tui/app.py`)

Stage E2 of the `design-first-increment` pipeline for Inc 9a. Graph only: no stub, mark or other change in `s19_app/` (`git diff --stat -- s19_app` stays empty). New functions are nodes whose `func:` starts with "new". Base: `4fef292`; line numbers are `4fef292` lines of `s19_app/tui/app.py` unless another file is named.

Inputs: `../E1-scope.md` (§1 scope, §3 slice, §4 Q1–Q9), `../E1-rulings.md` (binding: Q1–Q9, C1–C8), `interfaces-9a.md` (binding; changes only under §Proposals), `baseline-9a.md` and `baseline-notes.md` (callers 1–10, candidates C1–C8, probe p9a), `../../01-requirements.md` (HLR-172, HLR-172a, HLR-172b, LLR-172.1a/.1d/.1e/.1f/.1i call sites, LLR-172.3, LLR-172.4–.4c, LLR-172.5–.5g, LLR-172.6/.6a, AT-B100-12, AT-B100-13, the §3 token table), and `../../inc-8b/codewire/proto-8b-app.md` (format, and the `_project_folder_refusal` / token rows 2, 3 this design reuses).

**E3 round 1 applied (`../E3-rulings.md` R1–R13, LED .83).** A ruling wins over any older line of this file. The project route takes only an absolute typed path (step 0, R2; LLR-172.5h for a relative folder); a typed or picked project name is matched by listing against `list_projects`, never by spelling, and the on-disk name is loaded (R3); `_is_reserved_home` and the trailing-dot strip of P-4 are removed, because `list_projects` already excludes every reserved home (checked at `4fef292`, below); the dead classifier step (old step 10) is removed (R13); the Workarea Files label is `painted_names([p.name])` (R4); G1 records `os.path.abspath` (R1, P-1 revoked); the seams S1–S10 mean the same in G1 and G2 (R8); the C8 tool-script edits are dropped (R13).

**R3 check at `4fef292` (code read).** `list_projects` (`app.py:12057-12087`) iterates `sorted(self.workarea.iterdir())` and skips every entry whose case-folded on-disk name is in `reserved_folded = {home.casefold() for home in RESERVED_WORKAREA_HOMES}` (`app.py:12078-12082`); `RESERVED_WORKAREA_HOMES` (`workspace.py:43-53`) holds the 9 homes `temp`, `patches`, `templates`, `logs`, `crc`, `flows`, `flowsets`, `splits`, `reports`. `iterdir` yields long on-disk names only, so an 8.3 name (`TEMPLA~1`) or a stream spelling (`temp::$INDEX_ALLOCATION`) is never a listed name. **So `list_projects` already excludes every reserved home, and no separate reserved arm stays.** Residual: see design risk R-11 (an on-disk name ending in a dot).

**Owned nodes (7):**
- 5 changed: `refresh_files`, `load_from_path`, `load_a2l_from_path`, `_load_path_from_user_input`, `_handle_load_project`.
- 1 new: `_typed_load_route` (the typed-path classifier: absolute test, lexical path, link walk, listing match, §1.3 project test; returns an action and a reason word, paints nothing).
- 1 unchanged with a new caller: `_route_load_project` (Q3).
- Context node (unchanged, 2 new callers): `list_projects`, the one name source for the typed route and the project load.

**Why one new node, not inline.** `_typed_load_route` keeps every metadata read (one `lstat` per typed component, one listing of the work area, one folder listing) apart from the painting. The dispatcher then maps 6 reason words to 6 status lines. All arms of LLR-172.5b–.5f, .5h and the resolve-first mutant can be reached on the classifier with no app screen. Inlined, `_load_path_from_user_input` would be about 60 lines.

Every example line states what the requirement asks (target 9a) unless it says "holds at 4fef292". `W` = this work area (`<base>/.s19tool/workarea`); `ab` = a project holding `project.json` and `firmware.s19`; `<tmp>` = a temporary folder outside `<base>`; `<lad>` = `<tmp>/lad`, the test value of `LOCALAPPDATA` (C8); "the store" = `<lad>/s19_app/recent_sources.json`.

## Nodes

S19TuiApp.refresh_files
req: HLR-172b, LLR-172.4, LLR-172.4a, LLR-172.4b, LLR-172.4c, LLR-172.6, LLR-172.6a, AT-B100-13
in:
out: None
func: changed. (1) `list_view.clear()` (unchanged). (2) `files = list_workarea_files(self.workarea)`. The argument is the work-area root, not `temp`. G1 returns `Path`s (seam S3) of the regular, non-link direct children of `W/temp`, sorted, or `[]` when the folder is missing or cannot be listed. (3) For each `p`: `entry = ListItem(Label(safe_text(painted_names([p.name]))))` and `entry.data = p.name` (E3 R4, C5: the label is the project's one category scrub — Cc, Cf, Zl and Zp removed, an unpaired surrogate as U+FFFD, clipped to 120 characters ending in `…` — painted with markup off through `safe_text`'s `Text`; `data` is the on-disk name `_load_from_item` reads). (4) Log `files=len(files)`. The `temp_dir.glob("*")` (:7313) and the `is_file()` test (:7315) leave `app.py`, so `WORKAREA_TEMP` is no longer used to build a path here (LLR-172.4 census). No try/except: the empty-list arms are G1's (LLR-172.4c). Import: `list_workarea_files` joins the `.workspace` import (:251); `safe_text` (:44) and `painted_names` (:205) are already imported.
module: s19_app/tui/app.py
examples: (AT-B100-13, HLR-172b, LLR-172.6, root action_refresh_files) `W/temp` holds `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19` and `a<U+009B>b.s19` → `#files_list` `4` rows in `list_workarea_files` order. Their plain texts are `[bold]x.s19`, `[link=x]a.s19`, `[@click=app.bell]x.s19` and `ab.s19`, with `0` spans, `0` characters of category Cc and `0` raises, at `size=(118, 54)` and `(220, 60)`
examples: (LLR-172.6, R4) `W/temp` also holds `x<U+202E>gpj.s19` and `a<U+DC80>b.s19` → rows `xgpj.s19` and `a<U+FFFD>b.s19`: `0` characters of category Cf or Cs, `0` raises; a 130-character name → a label of `120` characters ending in `…` (`7` of `7` with the 4 above)
examples: (AT-B100-13 / LLR-172.6 negative control, executed on 4fef292) the `[bold]x.s19` row paints `Content('x.s19', spans=[Span(0, 5, style='bold')])` → RED. Mutations: `Label(p.name)` → the bold span is back → RED; `Label(Text(p.name))` with no scrub → U+009B painted → RED; `Label(safe_text(p.name))` (the E2 design, C0/C1 only) → the U+202E row keeps the Cf and the U+DC80 row the surrogate → RED (E3 S9-2)
examples: (LLR-172.6a, root on_list_view_selected) pick the `[bold]x.s19` row, the `a<U+009B>b.s19` row, the `x<U+202E>gpj.s19` row and the 130-character row → `item.data` equals each on-disk name, and `current_file.path.name` equals each on-disk name (`4` of `4`)
examples: (LLR-172.6a negative control) a mutation `entry.data = painted_names([p.name])` → the U+009B pick looks for `W/temp/ab.s19`, which is absent → nothing loaded → RED; the 130-character pick looks for the clipped name → RED. Declared: holds at 4fef292 (`data = item.name`)
examples: (LLR-172.4, TC-B100-37 census) AST census over `s19_app/` of `iterdir`/`glob`/`rglob`/`scandir`/`listdir`/`walk` on a path built from `WORKAREA_TEMP` → `1` function, `list_workarea_files` in `workspace.py`, and `0` in `app.py`. Base 4fef292: `refresh_files` (`app.py:7313`) → RED. A mutation keeping `temp_dir.glob("*")` beside the lister → `2` functions → RED
examples: (LLR-172.4a) `W/temp` holds `b.s19`, `a.hex`, `c.a2l`, `.staging/s.s19` and `sub/x.s19` → rows `a.hex`, `b.s19`, `c.a2l` (`3`), equal to `[p.name for p in list_workarea_files(W)]` (`0` differences), `0` rows for `.staging` or `sub`
examples: (LLR-172.4a empty) `W/temp` empty → `0` rows, log `files=0`
examples: (LLR-172.4b) `W/temp/l.s19`, a file symbolic link to an outside file, beside `a.hex` → `0` rows named `l.s19`, `1` row `a.hex`. Not run, never passed, when the test cannot create a file link. Base 4fef292: `is_file()` follows the link → `l.s19` listed → RED
examples: (LLR-172.4c missing) `W/temp` removed after start-up, then `r` → `0` rows, `0` raises
examples: (LLR-172.4c refused) the enumeration inside `list_workarea_files` raises `PermissionError` (injected) → `0` rows, `0` raises out of `refresh_files`. A mutation of G1 without the catch → the error leaves `refresh_files` → RED
examples: (TC-B99-36, holds at 4fef292) a fresh base folder → `0` rows; load `firmware.s19` → `1` row `firmware.s19`; `_files_list_names` (`tests/test_b99_load_project.py:59`, `str(Label.render())`) returns `firmware.s19` unchanged, because a plain name paints the same through `safe_text`

S19TuiApp.load_from_path
req: HLR-172, LLR-172.1a, LLR-172.1d, LLR-172.1e, LLR-172.1f, LLR-172.1i, LLR-172.1k, LLR-172.1l, LLR-172.3, AT-B100-12
in: Path path
out: None
func: changed. One new step (seams S1 and S2, rulings Q1 and C1) after `copy_into_workarea` returns (:12812) and its `copy_done` log, and before `set_progress(50, …)` (:12826) and `_start_load_worker(copied)` (:12830). The step: `if not contained_in_workarea(normalized, self.workarea): if not record_recent_source(normalized): self.logger.warning("Recent sources not updated: %r", str(normalized))`. It records `normalized`, the source path, never `copied`, the work copy; G1 stores its `os.path.abspath` form (E3 R1; proposal P-1 revoked; seam S7). There is no try/except: G1's contract is "never raises", and a caller-side catch would hide a G1 that leaks `OSError`, so LLR-172.1i's negative control could not fail (design risk R-5). There is no status line about the store (Q5). The early returns stay before the step: not found (:12794), unsupported suffix (:12799) and `WorkareaContainmentError` from the copy (:12813). So a load that fails before its copy never reaches the record (LLR-172.1d). The record runs on the calling thread before the worker starts (C1). A raising mutant therefore stops the load before the install. Import: `record_recent_source` joins the `.workspace` import; `contained_in_workarea` is already imported.
module: s19_app/tui/app.py
modify: [I/O: recent-sources store] (replace, through record_recent_source)
examples: (AT-B100-12 store half, HLR-172, LLR-172.1a, root action_load_file) `LOCALAPPDATA` = `<lad>`; type `<repo>/examples/case_01_basic_valid/firmware.s19` → the store reads `{"schema_version": 1, "sources": [{"path": "<repo, absolute>\\examples\\case_01_basic_valid\\firmware.s19", "kind": "s19"}]}` (`1` entry). `0` files named `recent_sources.json` under `<base>`, `.s19tool` included
examples: (HLR-172 / AT-B100-12 negative control, code read on 4fef292) `grep -rn LOCALAPPDATA s19_app` → `0` hits → `0` store files after the load → RED
examples: (LLR-172.1a order) after the `.s19` above, outside `<tmp>/x.a2l` (through load_a2l_from_path), `<tmp>/x.mac` and `<tmp>/x.hex` → `4` entries, kinds `hex`, `mac`, `a2l`, `s19`, newest first. `<tmp>/A.SREC` → `1` entry, kind `s19`
examples: (LLR-172.1a, Q1 call order) spies on an outside `.s19` load → `copy_into_workarea`, `record_recent_source(normalized)`, `_start_load_worker(copied)`, in that order, `1` call each. A mutation recording `copied` → the store path is `W\temp\firmware.s19` → RED
examples: (LLR-172.1d arm 3, over the cap) the store holds `1` entry; an outside `<tmp>/big.s19` of `2048` bytes with the placement cap lowered to `1024` (finding F-3: by `copy_into_workarea`'s default, not the module constant) → `1` status line holding `Cannot load file:`, `0` calls of `record_recent_source`, the store's SHA-256 unchanged
examples: (LLR-172.1d negative control) a mutation recording before the copy → the over-cap arm adds `1` entry → RED
examples: (LLR-172.1d, Q1 declared) an outside `<tmp>/bad.s19` that copies and then fails to parse in the worker → `1` entry recorded for `<tmp>\bad.s19`, and the worker's error line is painted
examples: (LLR-172.1e arm 1) type `W/ab/firmware.s19` → copied into `W/temp`, `0` calls of `record_recent_source`, the store holds `0` entries
examples: (LLR-172.1e negative control) a mutation without the `contained_in_workarea` test → the `W/ab/firmware.s19` arm adds `1` entry → RED
examples: (LLR-172.1e arm 3, caller _handle_select_variant :7606) `ab` open with variants `firmware` and `other`; switch to `other` → `load_from_path(W/ab/other.s19)`, `0` calls of `record_recent_source`, `0` entries
examples: (LLR-172.1f, S4, unset) `LOCALAPPDATA` deleted, working folder `<tmp>`, an outside `.s19` loaded → `record_recent_source` returns `False` and writes nothing. The image is installed (`current_file` set), with `0` raises, `1` log warning holding "Recent sources not updated", `0` status lines holding "recent" and `0` files named `recent_sources.json` under `<tmp>` or `<base>`
examples: (LLR-172.1f, S4, empty) `LOCALAPPDATA` = `""` → the same outcome as the unset arm
examples: (LLR-172.1f, S4, relative) `LOCALAPPDATA` = `relative\lad`, working folder `<tmp>` → the same outcome, and `<tmp>/relative/lad/s19_app/recent_sources.json` is absent
examples: (LLR-172.1i, data, replace fails) `os.replace` raises `PermissionError` (injected) → the image is installed as without the store, with `0` raises out of `load_from_path`, the store's SHA-256 unchanged, `0` staging files left, `1` log warning and `0` status lines about the store
examples: (LLR-172.1i, data, staging fails) the staging creation raises `OSError` (injected) → the same outcome as the replace arm
examples: (LLR-172.1i negative control) a mutation of `record_recent_source` letting the `OSError` out → it leaves `load_from_path` before `_start_load_worker`, so `current_file` stays `None` → RED. This is why the caller has no try/except (R-5)
examples: (LLR-172.3 arm 2) an outside load of `<tmp>/m4rk3r-9b/firmware.s19`, then Save project and a report → `0` occurrences of `m4rk3r-9b` in any file under `<base>` except `.s19tool/logs/`. G2 sends the source path only to `record_recent_source` and the log
examples: (Q2, caller on_mount :7226) start-up `load_path` = `<tmp>/x.s19` → `1` entry for `<tmp>\x.s19`
examples: (LLR-172.1l, through Load) type the UNC source `\\host\share\x.s19` (a test share; not run where none exists) → the image is installed, `record_recent_source` returns `False`, `1` log warning, the store's SHA-256 unchanged
examples: (LLR-172.1k, through Load) the store holds `3` entries and its open raises `PermissionError` (injected) → the image is installed, `1` log warning, the store's SHA-256 unchanged, `0` status lines about the store

S19TuiApp.load_a2l_from_path
req: HLR-172, LLR-172.1a, LLR-172.1d, LLR-172.1e, LLR-172.1i
in: Path path
out: None
func: changed. The same step as `load_from_path` (S1, S2, Q1): after the `copy_into_workarea` try/except (:12882–12888) and before `self.refresh_files()` (:12890), `if not contained_in_workarea(normalized, self.workarea): if not record_recent_source(normalized): self.logger.warning(...)`. The parse (`_load_a2l_data_with_cache`, :12901) comes after the record, so an A2L that copies and then fails to parse is recorded (Q1, declared). The early returns stay before the step: not found, unsupported suffix, the open project's validation error, `Project already has an A2L file.` and the guarded copy.
module: s19_app/tui/app.py
modify: [I/O: recent-sources store] (replace, through record_recent_source)
examples: (LLR-172.1a) outside `<tmp>/x.a2l` → the store's first entry is `{"path": "<tmp, absolute>\\x.a2l", "kind": "a2l"}`; the A2L is loaded (status "A2L loaded: x.a2l")
examples: (LLR-172.1a, call order) spies → `copy_into_workarea`, `record_recent_source`, `refresh_files`, `_load_a2l_data_with_cache`, in that order
examples: (LLR-172.1d arm 4) the store holds `1` entry; `ab` is open and holds `firmware.a2l`; type `<tmp>/y.a2l` → `1` status line `Project already has an A2L file.`, `0` copies, `0` calls of `record_recent_source`, the store's SHA-256 unchanged
examples: (LLR-172.1e arm 2, caller _load_from_item :13089) pick the `x.a2l` row → `load_a2l_from_path(W/temp/x.a2l)` (the byte-identical reuse), `0` calls of `record_recent_source`, `0` entries
examples: (LLR-172.1i, A2L, replace fails) `os.replace` raises `PermissionError` (injected), outside `<tmp>/x.a2l` → `current_a2l_path` set and A2L tags shown, with `0` raises, the store's SHA-256 unchanged, `1` log warning and `0` status lines about the store
examples: (LLR-172.1i, A2L, staging fails) the staging creation raises `OSError` (injected) → the same outcome; together with the 2 data arms that makes `4` of `4`

S19TuiApp._load_path_from_user_input
req: HLR-172a, LLR-172.5, LLR-172.5a, LLR-172.5b, LLR-172.5c, LLR-172.5d, LLR-172.5e, LLR-172.5f, LLR-172.5h, LLR-172.1d, AT-B100-12
in: Path path
out: None
func: changed (the dispatcher). (1) `action, value = self._typed_load_route(path)`. (2) `"project"` → `self._route_load_project(value)` (Q3): the Load-result panel opens as for a picked project. (3) `"a2l"` → `self.load_a2l_from_path(path)`, and `"data"` → `self.load_from_path(path)`, unchanged, with the raw `path` passed as at 4fef292. (4) `"refuse"` → one status line for the reason word (see "Status lines" below), with `t = painted_names([str(path)])` (scrubbed, clipped to 120 characters), then `self.set_status(safe_text(line).plain)` and `self.logger.warning("Typed load refused (%s): %r", value, str(path))`. The `File not found:` and `Unsupported file type:` lines (:12719, :12728) go; no test pins either (E1 §3, `grep -rn` → `0`).
module: s19_app/tui/app.py
examples: (AT-B100-12 typed half, HLR-172a, root action_load_file) after the store half, type the absolute `<base>/.s19tool/workarea/ab` with the path field focused → the status log holds "Loaded project 'ab'", and `LoadResultScreen` is on top. `LOAD_RESULT_CLOSE` closes it, and the store still holds the example's entry (`1`). Run at `(118, 54)` and `(220, 60)`. The two halves are independent at 9a (the typed half reads no store; the consume link is 9b's LLR-173.4; E3 R13)
examples: (LLR-172.5h) with a working folder other than the base folder, type `.s19tool/workarea/ab`, then `.s19tool/workarea/alias` (a junction to `ab`), then the root-relative `\…\.s19tool\workarea\ab` → `1` line each "File NOT loaded: 't' is not a supported file — check the path.", `0` calls of `_route_load_project`, `_reset_project_session`, `load_from_path` or `load_a2l_from_path` (`3` of `3`; the last two Windows only, R12)
examples: (LLR-172.5h negative control, code read on 4fef292) a folder gives `Unsupported file type: ` (empty suffix), neither token → RED
examples: (AT-B100-12 / HLR-172a negative control, executed on 4fef292) typed `W/ab` → `['Unsupported file type: ']`, no project; `W/ab/project.json` → `['Unsupported file type: .json']` → RED
examples: (LLR-172.5f, missing file) `<tmp>/missing.s19` → `1` line "File NOT loaded: '<tmp>\missing.s19' not found — check the path.", `0` calls of `load_from_path` or `_route_load_project`
examples: (LLR-172.5f, missing folder) `W/nope` → `1` line holding `not found` and `check the path`, `0` loads
examples: (LLR-172.5f negative control, code read on 4fef292) `File not found: <path>` holds `not found` but not `check the path` → RED
examples: (LLR-172.5e) `<tmp>/firmware` (no suffix), `<tmp>/notes.txt` and `<tmp>/x.json` → `1` line each holding `not a supported file` and `check the path`, `0` loads, `0` files copied into `W/temp` (`3` of `3`). Base: `Unsupported file type: <suffix>` with neither token → RED
examples: (LLR-172.5b, LLR-172.5c, LLR-172.5d) each refusal of `_typed_load_route` → `1` status line holding the reason token and the next-step token of the "Status lines" table, `0` calls of `_route_load_project`, `_reset_project_session`, `load_from_path` or `load_a2l_from_path`
examples: (LLR-172.1d arms 1–2) the store holds `1` entry; type `<tmp>/missing.s19`, then `<tmp>/notes.txt` → the store's SHA-256 unchanged after each, `0` calls of `record_recent_source`
examples: (Q3 seam) typed `W/ab` → `_route_load_project("ab")` `1` call (spy) and `0` direct calls of `_handle_load_project` from the dispatcher. A mutation calling `_handle_load_project` directly → no `LoadResultScreen` → RED against Q3
examples: (painting) typed `<tmp>/[bold]<U+202E>x` (missing) → the painted line holds `[bold]x` as literal text, with `0` spans, `0` characters of category Cc or Cf, and `not found`
examples: (caller on_mount, R-1) start-up `load_path` = `W/ab` → project `ab` loaded and `LoadResultScreen` on top after mount

S19TuiApp._typed_load_route
req: HLR-172a, LLR-172.5, LLR-172.5a, LLR-172.5b, LLR-172.5c, LLR-172.5d, LLR-172.5e, LLR-172.5f, LLR-172.5h
in: Path path
out: tuple[str, str] route
func: new. Returns `("project", name)` (`name` = the on-disk name of a listed project), `("data", "")`, `("a2l", "")` or `("refuse", reason)`, with reason one of `not found`, `not a supported file`, `not a project`, `outside`, `link`, `unreadable`. It reads metadata, at most one listing of the work area and one folder listing, writes nothing and never raises: every `OSError` is mapped to a reason. Steps:
- (0) `text = str(path).strip().strip('"')` (the stripping `resolve_input_path` does). `Path(text).is_absolute()` false (E3 R2; on Windows a drive and a root are both needed, so `\x` and `C:x` are relative) → the file branch only: `normalized = resolve_input_path(path, self.base_dir)`; `None` → `("refuse", "not found")`; `os.path.isdir(normalized)` → `("refuse", "not a supported file")` (LLR-172.5h); suffix in `A2L_EXTENSIONS` → `("a2l", "")`; in `SUPPORTED_EXTENSIONS` → `("data", "")`; else `("refuse", "not a supported file")`. The base-folder fallback (which resolves junctions) therefore never feeds the project route (closes F-5 / S9-6). Steps (1)–(11) run for an absolute path only.
- (1) `normalized = resolve_input_path(path, self.base_dir)`; for an absolute candidate it returns the candidate unchanged or `None` (its fallbacks run only for a relative one, `workspace.py:2025`). `None` → `("refuse", "not found")`.
- (2) `typed = os.path.abspath(normalized)`. This is lexical (GetFullPathNameW): it folds `.` and `..`, the separators and a component's trailing dots, and follows no link (C2: no `resolve()` before the link check). `w = os.path.abspath(self.workarea)`. `inside` = `normcase(typed) == normcase(w)` or `normcase(typed)` starts with `normcase(w) + os.sep`. `parts` = the components of `typed` after `w`, in the typed spelling.
- (3) `is_manifest = name.casefold() == "project.json"` and `suffix = PurePath(typed).suffix.lower()`.
- (4) Not inside: `is_manifest` → `("refuse", "outside")`; `os.path.isdir(typed)` → `("refuse", "outside")`; suffix in `A2L_EXTENSIONS` → `("a2l", "")`; suffix in `SUPPORTED_EXTENSIONS` → `("data", "")`; else `("refuse", "not a supported file")`.
- (5) Inside, not `is_manifest`, and the suffix is a data or A2L suffix → `("data", "")` or `("a2l", "")`. A file inside the work area keeps today's file route (LLR-172.1e arm 1). There is no link walk for it, because LLR-172.5d names folder and `project.json` paths.
- (6) Inside, otherwise, the link walk. For each prefix `w/parts[:i]`, `i = 1 … len(parts)`, run `os.lstat`. `S_ISLNK` or `_is_reparse_point` → `("refuse", "link")`. `FileNotFoundError` → `("refuse", "not found")`, a race only after (1). Any other `OSError` → `("refuse", "unreadable")`.
- (7) `folder_parts = parts[:-1]` when `is_manifest`. Otherwise the last `lstat` must be a folder (`S_ISDIR`), else `("refuse", "not a supported file")`: a regular file inside with another suffix, such as `W/ab/notes.txt`.
- (8) `len(folder_parts) != 1` → `("refuse", "not a project")`. This covers the work area itself, a project's sub-folder and a `project.json` below a project. `typed_name = folder_parts[0]`.
- (9) Listing match (E3 R3): `listed = self.list_projects()` (one listing of W; an `OSError` → `("refuse", "unreadable")`); `name` = the entry of `listed` with `os.path.normcase(entry) == os.path.normcase(typed_name)`; none → `("refuse", "not a project")`. `list_projects` never lists a reserved home (R3 check above), a link (its `_project_folder_refusal`) or a file, and yields long on-disk names only, so a stream spelling (`temp::$INDEX_ALLOCATION`), an 8.3 name (`TEMPLA~1`), a trailing-dot spelling (`temp.` → `abspath` gives `temp`) and every case of a reserved home match nothing. `W/temp` is never enumerated (LLR-172.4). From here the route uses `name`, the on-disk spelling, never the typed text.
- (old step 10, `_project_folder_refusal` again) removed (E3 R13 / A9-10): after (6), (8) and (9) a plain listed direct child cannot fail it, and `_handle_load_project` runs it again before any reset.
- (11) The §1.3 content test on `self.workarea / name` (C4: the one app-side copy of §1.3, unified at 9b). The folder is a project when `os.lstat(folder / "project.json")` is a regular file and not a reparse point, or when `validate_project_files(folder)` returns a data file, an A2L file or an error (a folder with 2 MAC files is still a project; its load paints the error). Then → `("project", name)`. An `OSError` while listing → `("refuse", "unreadable")`. Otherwise → `("refuse", "not a project")`: an empty folder (Q9) or a folder of other files.
module: s19_app/tui/app.py
examples: (LLR-172.5) `W/ab` → `("project", "ab")`
examples: (LLR-172.5, `..`) `W/temp/../ab` → `("project", "ab")`. `abspath` folds the `..` before any `lstat`, so `W/temp` is not inspected
examples: (LLR-172.5, case) `W` spelled in upper case, then `/ab` → `("project", "ab")` (`normcase` prefix); `W/AB` → `("project", "ab")`, the on-disk name from the listing (R3; closes R-2). Through the dispatcher: `4` loads of `ab` in all, `current_project == "ab"` each time (the two case arms Windows only, R12)
examples: (LLR-172.5 negative control, executed on 4fef292) `W/ab` and `W/temp/../ab` → `['Unsupported file type: ']` → RED
examples: (LLR-172.5a) `W/ab/project.json` and `W/ab/PROJECT.JSON` → `("project", "ab")` (`2` of `2`)
examples: (LLR-172.5a, below a project) `W/ab/flows/project.json` → `("refuse", "not a project")`, because its folder has 2 components
examples: (LLR-172.5b, reserved homes) `W/temp` holding a work copy, `W/TEMP` and `W/patches` → `("refuse", "not a project")` at step (9), with `0` calls of `validate_project_files` and `0` files written (`3` of `3`)
examples: (LLR-172.5b, R3, E3 S9-1) `W/temp::$INDEX_ALLOCATION`, `W/TEMPLA~1` (the 8.3 name of `templates`, holding `t.s19`) and `W/temp.` → `("refuse", "not a project")` at step (9) (no listed name matches), `0` calls of `validate_project_files`, `0` files written (`3` of `3`; Windows only, the 8.3 arm not run when the volume makes no 8.3 names, R12)
examples: (LLR-172.5b negative control, R3) a mutation replacing step (9) with a case-folded test against `RESERVED_WORKAREA_HOMES` (the E2 design) → `W/temp::$INDEX_ALLOCATION` passes the walk, the reserved test and the §1.3 test → `("project", "temp::$INDEX_ALLOCATION")` → RED (E3 S9-1 P2)
examples: (R-10, declared) a project `abcdefghij` typed by its 8.3 name `W/ABCDEF~1` → `("refuse", "not a project")` (fail closed: only listed spellings route)
examples: (step 9 listing error) `list_projects` raising `PermissionError` (injected) → `("refuse", "unreadable")`
examples: (LLR-172.5b, empty folder) `W/empty` → `("refuse", "not a project")` (Q9)
examples: (LLR-172.5b, sub-folder) `W/ab/flows` → `("refuse", "not a project")`
examples: (LLR-172.5b, the work area) `W` and `W\` → `("refuse", "not a project")` (`parts` is empty)
examples: (LLR-172.5b negative control, executed S-01 probe) `validate_project_files(W/temp)` accepts the work copy, so a route without step (9) loads `temp` → RED; on 4fef292 `W/temp` → `['Unsupported file type: ']`, neither token → RED
examples: (LLR-172.5h) `.s19tool/workarea/ab` (found by the base-folder fallback), `.s19tool/workarea/alias` (a junction to `ab`; the fallback's `resolve()` follows it) and `\…\.s19tool\workarea\ab` (root-relative) → `("refuse", "not a supported file")` at step (0), `0` `lstat` calls of the walk, `0` calls of `list_projects` (`3` of `3`)
examples: (LLR-172.5h negative control) a mutation testing `os.path.isabs(text)` (true for `\x` on Python 3.12) → the root-relative arm reaches the project route → `("project", "ab")` → RED; a mutation without step (0) → `.s19tool/workarea/alias` resolves to `W/ab` → `("project", "ab")` → RED
examples: (step 0, relative file) `examples/case_01_basic_valid/firmware.s19` typed relative → `("data", "")` (today's file route, unchanged)
examples: (LLR-172.5c, outside folder) `<tmp>/elsewhere/P` holding `project.json` and an image → `("refuse", "outside")`
examples: (LLR-172.5c, outside manifest) `<tmp>/elsewhere/P/project.json` → `("refuse", "outside")`
examples: (LLR-172.5c, another work area) `<tmp>/other/.s19tool/workarea/R` → `("refuse", "outside")`
examples: (LLR-172.5c, base folder) `<base>` → `("refuse", "outside")`. Through the dispatcher: `4` of `4` arms paint 1 line each with `outside the work area` and `copy the folder into the work area`
examples: (LLR-172.5c negative control) a mutation routing any folder that holds a `project.json` → `<tmp>/elsewhere/P` loads → RED
examples: (LLR-172.5d, junction folder) `W/alias`, a junction to `W/ab` → `("refuse", "link")`, `0` session resets
examples: (LLR-172.5d, junction manifest) `W/alias/project.json` → `("refuse", "link")`: the walk meets `alias` first
examples: (LLR-172.5d, junction above) `W/sub/P` with `W/sub` a junction to another work area → `("refuse", "link")`, `0` session resets
examples: (LLR-172.5d negative control) a mutation calling `Path(typed).resolve()` before the walk → `W/alias` becomes `W/ab` → `("project", "ab")` → RED
examples: (LLR-172.5e) `<tmp>/firmware`, `<tmp>/notes.txt` and `<tmp>/x.json` → `("refuse", "not a supported file")` (`3` of `3`); inside, `W/ab/notes.txt` → the same, by step (7)
examples: (LLR-172.5f) `<tmp>/missing.s19` and `W/nope` → `("refuse", "not found")` (`2` of `2`)
examples: (LLR-172.1e routing) `W/ab/firmware.s19` → `("data", "")`, `0` `lstat` calls of the walk (spy)
examples: (token row "could not be read", 8b F7) `W/locked`, whose listing raises `PermissionError` (injected into `validate_project_files`) → `("refuse", "unreadable")`
examples: (§1.3, A2L-only, 8b HLR-171a) `W/a2lonly` holding only `firmware.a2l` → `("project", "a2lonly")`
examples: (F-2, trailing dot) `W/temp.` → `abspath` gives `W\temp` → no listed name matches `temp` → `("refuse", "not a project")` (R3; no strip needed)

S19TuiApp.list_projects
req: LLR-172.5, LLR-172.5b, LLR-172.5g
in:
out: List[str] projects
func: unchanged (`app.py:12057-12087`; C4, unified at 9b). `sorted(self.workarea.iterdir())`; skips every entry whose `name.casefold()` is in `{home.casefold() for home in RESERVED_WORKAREA_HOMES}` (`:12078-12082`), then every entry `_project_folder_refusal` refuses (a link, an unreadable entry), then every non-folder; returns the on-disk names. New callers at 9a: `_typed_load_route` step (9) and `_handle_load_project` (E3 R3), the one name source for both. Cost: one listing of W plus one `lstat` per child, on the UI thread, per typed project path or project load (estimated, not measured; work areas hold tens of folders).
module: s19_app/tui/app.py
examples: (R3 check, holds at 4fef292 by code read) W holds `ab`, `temp`, `templates`, `patches`, `alias` (a junction) and `notes.txt` → `["ab"]`: `0` reserved homes, `0` links, `0` files
examples: (R3, holds at 4fef292) the 9 entries of `RESERVED_WORKAREA_HOMES`, each created at W's root in upper case → `0` of them listed (the case-fold runs on the on-disk name)
examples: (R3, Win32 names, holds by construction) `iterdir` yields `templates`, never `TEMPLA~1`, and never a stream spelling → neither can equal a listed name

S19TuiApp._handle_load_project
req: HLR-172a, LLR-172.5g, LLR-171.4e, LLR-171.4f
in: Optional[str] name
out: None
func: changed (E3 R3). One new step after the existing `_project_folder_refusal` refusal (:11679-11699) and the `exists()` "Project not found" return (:11700-11703), and before `validate_project_files` (:11704) and the reset — so the link, outside, unreadable and not-found refusals of LLR-171.4e / LLR-171.4f keep their tokens and run first. The step: `listed = self.list_projects()` (an `OSError` → the existing `could not be read` row: "Project NOT loaded: 'n' could not be read — check that the folder can be opened, then load again.", return); `match` = the entry with `os.path.normcase(entry) == os.path.normcase(name)`; none → `self.set_status(safe_text(f"Project NOT loaded: '{painted_names([name])}' is not a project — pick a project in the list.").plain)`, then `self.logger.warning("Project load refused (not listed): %r", name)`, then return; a match → `name = match` and `project_dir = self.workarea / name` (the on-disk spelling is loaded and shown). Nothing else changes. The refusal composes no announcement, so `_route_load_project` opens no panel. No `_is_reserved_home`: `list_projects` already excludes every reserved home (R3 check above).
module: s19_app/tui/app.py
modify: [Data: S19TuiApp.current_project_dir] (unchanged on every refusal)
examples: (LLR-172.5g) `W/temp` holds a work copy; `_handle_load_project("temp")` → `1` line holding `not a project` and `pick a project in the list`, `current_project` unchanged, `_reset_project_session` `0` calls, `W/temp/project.json` absent
examples: (LLR-172.5g) `_handle_load_project("TEMP")` and `("patches")` → the same refusal, `0` resets
examples: (LLR-172.5g, R3, E3 S9-1) `_handle_load_project("temp::$INDEX_ALLOCATION")`, `("TEMPLA~1")` (`templates` holding `t.s19`) and `("temp.")` → each passes `_project_folder_refusal` (textual parent W, a plain folder) and `exists()`, then matches no listed name → the same refusal, `0` resets, `W/temp/project.json` and `W/templates/project.json` absent (`6` of `6` with the 3 above; all but `temp` / `patches` Windows only, R12)
examples: (LLR-172.5g control) `ab` on disk; `_handle_load_project("AB")` → 1 load, `current_project == "ab"` (Windows only)
examples: (LLR-172.5g negative control, executed on 4fef292, probe U4/U5) `_handle_load_project('temp')` → `Loaded project 'temp' …`, `current_project = temp` → RED. A mutation testing the name case-folded against `RESERVED_WORKAREA_HOMES` instead of the listing (the E2 design) → `temp::$INDEX_ALLOCATION` and `TEMPLA~1` load → RED
examples: (order kept, LLR-171.4e / LLR-171.4f, holds) `_handle_load_project("alias")` (a junction) → the `link or junction` line, not `not a project`; `("../other/R")` → the `outside the work area` line; `("missing")` → `Project not found: missing` (each before the new step)
examples: (holds at 4fef292) `_handle_load_project("ab")` → "Loaded project 'ab'". The 20 test files that call it (F-1): by the order above a test name reaches the new step only when it exists as a plain direct child of W, which `list_projects` lists unless reserved (`0` reserved names in the census) — code read, not run; E4 re-runs the census

S19TuiApp._route_load_project
req: HLR-172a, LLR-172.5
in: Optional[str] name
out: None
func: unchanged (:7444). Its new caller is the typed dispatcher (Q3), beside the Load project dialog (:7442).
module: s19_app/tui/app.py
examples: (Q3) typed `W/ab` → `_handle_load_project("ab")` composes a new announcement → `LoadResultScreen` pushed `1` time
examples: (Q3) typed `W/temp` → refused by `_typed_load_route` → `_route_load_project` `0` calls, `0` screens pushed
examples: (holds at 4fef292) Load project dialog pick `ab` → the panel opens (test_b100 LLR-178.3 tests)

## Status lines (the dispatcher's 6 reason words; all §3 rows already exist, Q7)
| Reason word | Line (`t` = the typed text through `painted_names`) | Tokens (§3 row) |
|---|---|---|
| `not found` | File NOT loaded: 't' not found — check the path. | `not found` / `check the path` |
| `not a supported file` | File NOT loaded: 't' is not a supported file — check the path. | `not a supported file` / `check the path` |
| `not a project` | Project NOT loaded: 't' is not a project — pick a project in the list. | `not a project` / `pick a project in the list` |
| `outside` | Project NOT loaded: 't' is outside the work area — copy the folder into the work area. | `outside the work area` / `copy the folder into the work area` |
| `link` | Project NOT loaded: 't' passes through a link or junction — pick a project in the list. | `link or junction` / `pick a project in the list` |
| `unreadable` | Project NOT loaded: 't' could not be read — check that the folder can be opened, then load again. | `could not be read` / `check that the folder can be opened, then load again` |
The not-listed refusal of `_handle_load_project` paints the `not a project` row with the name in place of `t`. The relative-folder refusal (LLR-172.5h) paints the `not a supported file` row.

## Entities

[I/O: recent-sources store]
desc: `%LOCALAPPDATA%\s19_app\recent_sources.json`, outside every work area. G1 owns every read and write. G2 only calls `record_recent_source` after a successful copy of an outside source, and does not read the store at 9a (S5: the 9b dialog paints it).
sequence:
  recordOutside: S19TuiApp.load_from_path → copy_into_workarea wins → contained_in_workarea (False) → record_recent_source → S19TuiApp._start_load_worker
  recordA2L: S19TuiApp.load_a2l_from_path → copy_into_workarea wins → contained_in_workarea (False) → record_recent_source → S19TuiApp.refresh_files → S19TuiApp._load_a2l_data_with_cache
  insideSource: S19TuiApp.load_from_path → copy_into_workarea wins → contained_in_workarea (True) → expect none (0 record calls)
  failedBeforeCopy: S19TuiApp._typed_load_route (refuse) / copy_into_workarea (raises) → expect none (store bytes unchanged)

[I/O: workarea temp]
desc: `W/temp`, the folder every file load copies into. It is enumerated only by `list_workarea_files` (G1); `refresh_files` paints its result.
sequence:
  repaint: S19TuiApp.refresh_files → list_workarea_files → S19TuiApp.refresh_files wins (Label(safe_text(name)), data = name)
  pick: S19TuiApp._load_from_item (reads item.data) → S19TuiApp.load_selected_file / S19TuiApp.load_a2l_from_path

[Data: S19TuiApp.current_project_dir]
desc: the open project's folder. The typed route changes it only through `_route_load_project` → `_handle_load_project`, after every refusal has been decided.
sequence:
  typedProject: S19TuiApp._load_path_from_user_input → S19TuiApp._typed_load_route (is_absolute → abspath → link walk → S19TuiApp.list_projects match (on-disk name) → §1.3 content) → S19TuiApp._route_load_project → S19TuiApp._handle_load_project (_project_folder_refusal → exists → S19TuiApp.list_projects match → validate_project_files) → S19TuiApp._reset_project_session → S19TuiApp._handle_load_project wins → LoadResultScreen
  typedRelative: S19TuiApp._typed_load_route (not is_absolute → file branch; a folder → refuse "not a supported file") → expect none (0 project routes)
  typedRefused: S19TuiApp._typed_load_route (refuse) → expect none (0 resets, 0 files written)

## Callers and what changes for each

| Caller (line) | Reaches | What changes for it |
|---|---|---|
| `on_mount` (:7193, :7226) | `refresh_files`; `_load_path_from_user_input(load_path)` | The start-up list paints through the lister with literal names. A start-up outside file is recorded (Q2). A start-up project folder path now loads the project and opens the Load-result panel on top after mount (R-1). A start-up missing or unsupported path paints the new token lines. |
| `_handle_load_dialog` (:12765, `call_after_refresh`) | `_load_path_from_user_input` | Nothing in the function. Its deferred call now meets the classifier, so a typed project path opens the panel after the dialog has closed. A typed refusal is a status line, because the dialog is already closed (`#load_reason` comes at 9b, LLR-173.5). |
| `_handle_select_variant` (:7606) | `load_from_path(variant path inside W/<project>)` | Nothing it can see: the source is inside W → `0` record calls (LLR-172.1e arm 3). `_pending_variant_id` handling is unchanged. |
| `_load_from_item` (:13089, :13091) | `load_a2l_from_path(W/temp/x.a2l)`; `load_selected_file` | A2L pick: inside W → `0` record calls (LLR-172.1e arm 2). A data pick goes through `load_selected_file` and never reaches the record. It reads `item.data`, which is still the on-disk name (C5, LLR-172.6a). |
| `_route_load_project` (:7444) | `_handle_load_project` | Gains the typed dispatcher as a second caller (Q3). A name the project list does not list is refused before any announcement → no panel. |
| `action_refresh_files` (:7322), `_handle_save_dialog` (:10596), `load_from_path` (:12834), `load_a2l_from_path` (:12890) | `refresh_files` | They repaint through the lister. No caller reads the labels; `tests/test_b99_load_project.py:59` reads `str(Label.render())`, which is unchanged for plain names. |
| 20 test files (`grep -rln "_handle_load_project(" tests` at 4fef292) | `_handle_load_project` | `0` pass a reserved name (case-insensitive grep → `0` hits). The listing step runs after the link, outside and not-found refusals, so a name those tests pass reaches it only as an existing plain direct child, which `list_projects` lists (code read, not run; E4 re-runs the census) (F-1). |

## C8 ruling: what must point LOCALAPPDATA away from the real store

`recent_store_path()` must read `LOCALAPPDATA` when it is called, never cache it at import (proposal P-3, seam S9). Otherwise the fixture below has no effect. Every fixture value derives from `tmp_path`, never a literal drive path (R5 / E3 S9-3).
- `tests/conftest.py`:
  - an autouse function fixture, `monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "lad"))`, for every test;
  - a session-scope guard that records the real `%LOCALAPPDATA%\s19_app\recent_sources.json` SHA-256 (or its absence) from `os.environ` before any function fixture runs, and fails the session if it changed (LLR-172.1, LED .41).
  - The LLR-172.1f arms override the fixture inside the test (`delenv`, `""`, `relative\lad`).
- Tests that start subprocesses (`tests/support/b100_links.py`, `tests/support/b100_projects.py`, `test_b99_corpus.py`, `test_b99_staging.py`, `test_b100_save_guards.py`, `test_a2l_f841_cleanup.py`, `test_b97_*`, `test_checks_engine.py`, `test_b97_chips_help.py`) inherit the patched `os.environ`. `grep -rn "env=" tests` → `0` hits, so none builds its own environment. Nothing further is owed.
- `tools/e13/run.py` and `docs/images/capture_readme_media.py`: **no edit** (E3 R13 drops the C8 tool edits). By code read neither reaches a record: the first only drives `_route_load_project("P")`, the second installs through `_apply_prepared_load` (F-4). The autouse `tests/conftest.py` fixture stays.
- Probe scripts of this increment (`.dev-flow/2026-10-26-batch-100/inc-9a/` and `evidence/inc-9a/`, E4–E6) that drive `load_from_path`, `load_a2l_from_path` or the typed route: set `LOCALAPPDATA` to their scratch folder (same rule; added by this design).
- Not covered, on purpose: `prototypes/cmdbar_a2bdiff.tui_prototype.py` and `prototypes/crc_designer.b59.inapp_prototype.py` run the real app interactively. A load the operator makes there is recorded as in the app.

## Seams with G1 (`workspace.py`)

| Id | Seam | G2 side (this design) | Example |
|---|---|---|---|
| S1 | record call after copy | `record_recent_source(normalized)` after `copy_into_workarea` returns and before the worker (data) or the parse (A2L); never called with `copied` | load_from_path "Q1 call order"; load_a2l_from_path "call order" |
| S2 | the inside test is the caller's | `contained_in_workarea(normalized, self.workarea)`; inside → no call | load_from_path LLR-172.1e arms 1 and 3; load_a2l_from_path arm 2 |
| S3 | the lister returns `Path`s | `refresh_files` uses `p.name` for the label (`painted_names`, markup off, E3 R4) and for `item.data` | refresh_files LLR-172.4a / LLR-172.6 / LLR-172.6a |
| S4 | `None` store path = no write, no status | `record_recent_source` returns `False` → `1` log warning, `0` status lines; G2 never calls `recent_store_path` itself | load_from_path LLR-172.1f (3 arms) |
| S5 | the store problem word | not consumed by G2 at 9a: `read_recent_sources` has `0` callers in `app.py` (9b paints it) | — |
| S6 | who logs a failed record | the caller's one WARNING is the only one; G1 logs below WARNING (P-2 accepted, P9a-G1-1 rejected), so LLR-172.1i's "1 log warning" holds | load_from_path LLR-172.1i, LLR-172.1k |
| S7 | the argument of the record call | G2 passes `normalized` (the source), never `copied`; G1 records `os.path.abspath` of it (E3 R1; P-1 revoked) | load_from_path "Q1 call order" |
| S8 (test seam) | the TC-B100-37 census shape | `refresh_files` loses `temp_dir.glob("*")` (:7313); the only temp enumeration is G1's `os.scandir(temp_dir)` | refresh_files LLR-172.4 census |
| S9 | `LOCALAPPDATA` read at call time | load-bearing for C8 (P-3 accepted) | C8 section |
| S10 | every suffix G2 sends has a kind | the classifier sends to the load functions only `SUPPORTED_EXTENSIONS` ∪ `A2L_EXTENSIONS` (`.s19 .srec .hex .ihex .mac .a2l`), the same sets `recent_kind` maps (C6), so no G2 record is refused for its kind | load_from_path LLR-172.1a `A.SREC` |

## Findings

finding F-1 the reverse census of `_handle_load_project` callers is 20 test files, not 13
anchor: S19TuiApp._handle_load_project
seen: `grep -rln "_handle_load_project(" tests | wc -l` → `20` at 4fef292 (E1 §3 says 13). `grep -rni '_handle_load_project("(crc|flows|flowsets|reports|splits|templates|logs|temp|patches)' tests` → `0`.
cause: a different count rule in E1 (by reading; not traced).
effect: none for the design: no test passes a reserved name.
decision: recorded; E4 re-runs the census.

finding F-2 a trailing dot makes a reserved home pass a case-fold test
anchor: S19TuiApp._is_reserved_home
seen: executed in the scratch folder (not the repository) with system Python on Windows 11. With `W/temp` holding `f.s19`: `Path(W, "temp.").exists()` → `True`, `os.listdir(W/"temp.")` → `['f.s19']`, `os.path.abspath` → `…\W\temp` (dot dropped), `os.path.normpath` → `…\W\temp.` (dot kept). `W/"temp "` → `WinError 3` in `os.lstat`.
cause: Win32 path normalisation drops trailing dots from a component.
effect: `_handle_load_project("temp.")` passes `name.casefold()` and `_project_folder_refusal` (textual parent equal, a plain folder) and would load `W/temp`. This is inferred, not run through the app. The typed route is safe because it uses `abspath`.
decision (superseded by E3 R3): the strip and `_is_reserved_home` are removed. Names are matched against `list_projects`, so `temp.` (typed: `abspath` gives `temp`; picked: `_handle_load_project("temp.")`) matches no listed name and is refused; the `temp.` arm is in LLR-172.5b and LLR-172.5g. The `temp ` arm is dropped (it fails at `lstat` on `4fef292` already, A9-8).

finding F-3 lowering the placement cap needs `copy_into_workarea`'s default, not the module constant
anchor: S19TuiApp.load_from_path
seen: `copy_into_workarea(source, destination, max_size_bytes: int = DEFAULT_COPY_SIZE_CAP_BYTES, …)` (`workspace.py:1422-1425`) binds the default at import. `load_from_path` passes no cap (:12812). The 8b idiom `monkeypatch.setattr(workspace_module, "DEFAULT_COPY_SIZE_CAP_BYTES", cap)` (`tests/test_b100_project_homes.py:1082`) does not reach it.
cause: default argument binding (the same class as 8b R-4).
effect: LLR-172.1d's over-cap arm would copy and record when the test lowers only the constant, so its RED would come from the wrong cause.
decision: test note for E4: patch `workspace.copy_into_workarea.__defaults__`, or use a source over the real cap. No source change.

finding F-4 the two C8 scripts never reach the record by today's code
anchor: S19TuiApp.load_from_path
seen: `tools/e13/run.py:120-127` drives `_route_load_project("P")`. `docs/images/capture_readme_media.py:88` calls `_apply_prepared_load`. Neither calls `load_from_path`, `load_a2l_from_path` or `_load_path_from_user_input` (by code read).
cause: both install without the copy route.
effect: under this design neither writes the store. C8's environment setting is defence for a later edit.
decision (E3 R13): the two script edits are dropped; neither script reaches a record. The autouse `tests/conftest.py` fixture stays.

finding F-5 a relative typed path found by the base or repo fallback is already resolved
anchor: S19TuiApp._typed_load_route
seen: `resolve_input_path` returns an existing candidate unchanged, but its base and repo fallbacks return `(base_dir / candidate).resolve()` (`workspace.py:2026`, `:2031`).
cause: older than 9a.
effect: typed `.s19tool/workarea/alias`, from a working folder that is not the base folder, reaches the walk as `W/ab` (the junction already followed). It then loads `ab` instead of refusing `link or junction`. This applies to relative spellings only; Q4's tests type absolute paths.
decision (E3 R2, closed): the project route runs for an absolute typed path only (step 0); a relative folder is refused with `not a supported file` / `check the path` (LLR-172.5h), so the fallback's resolved path never reaches the walk.

## Design risks
R-1 (start-up modal). A command-line project path now opens the Load-result panel on top after mount (caller 2 of baseline-notes). A test that starts the app with `load_path` set to a project sees the modal. Low impact; consistent with Q2 and Q3.
R-2 (typed name spelling) — CLOSED by E3 R3: option (b) taken; `W/AB` loads the listed on-disk name `ab` (LLR-172.5 arm), and `_handle_load_project("AB")` does the same (LLR-172.5g control).
R-3 (classification by the typed name). A folder whose name ends in a data suffix (`W/x.s19/`) is sent to the file route, as at 4fef292 (same router). This is older than 9a, by reading; not run.
R-4 (record before the worker). The store read (at most 65 537 bytes) and its write run on the main thread before `_start_load_worker`. Estimated under 5 ms per load (not measured); ruled by Q1/C1. E4 logs the elapsed time once.
R-5 (no caller try/except). G2 relies on G1's "never raises" contract so that LLR-172.1i's negative control stays RED for a leaking G1. If G1 did leak in production, the load would stop before the install with an unhandled exception. The TC-B100-34 mutant arm is the guard.
R-6 (relative typed paths, F-5) — CLOSED by E3 R2 (step 0, LLR-172.5h).
R-7 (outside, read lexically). An outside path that is a junction into W (`<tmp>/j/ab`, `j` → `W`) is refused with `outside the work area`, although it resolves inside. This is conservative and matches C2 (lexical first).
R-8 (painted path length). `painted_names` clips the typed path at 120 characters (`…`); the tokens come after it and are never clipped.
R-9 (`\\?\` spellings of W). The `normcase` prefix test fails, so the path is classified as outside. This is consistent with 8b S3-10, where the Save parent refuses the same spelling.
R-10 (8.3 name of a project, E3 R3, declared). A project typed by its 8.3 short name (`W/ABCDEF~1` for `abcdefghij`) is refused `not a project`: only listed spellings route. Fail closed; the 9b dialog picks by name.
R-11 (an on-disk folder name ending in a dot, not run). A folder literally named `temp.` can exist only when created through a `\\?\` path. `list_projects` would list it (`"temp.".casefold()` is not a reserved name), and `self.workarea / "temp."` opens `W\temp` through Win32, so a pick of it in the Load project dialog would load the contents of `temp`. Typing cannot reach it: a `\\?\` spelling is refused as outside (R-9), and a plain spelling folds to `temp`, which is not listed. Pre-existing at `4fef292` in the Load project dialog (same `list_projects`, unchanged at 9a, C4); not reachable through any app write. Recommendation: BACKLOG — `list_projects` skips a name ending in a dot or space, as the 8b save-as walk already refuses such names (LLR-171.1k).

## Windows-only arms (E3 R12; declared in the packet beside P9a-G1-6)
Each is reported "not run" on the Linux CI (`.github/workflows/tui-ci.yml:25`, `runs-on: ubuntu-latest`) and executed on Windows for the gate; none is reported passed when skipped.
| Requirement | Arms | Reason |
|---|---|---|
| LLR-172.5 | `<workarea>` in upper case + `/ab`; `<workarea>/AB` | case-insensitive file system |
| LLR-172.5a | `<workarea>/ab/PROJECT.JSON` | case-insensitive file system |
| LLR-172.5b | `<workarea>/TEMP`; `temp::$INDEX_ALLOCATION`; `TEMPLA~1`; `temp.` | case-insensitive file system; Win32 stream, 8.3 and trailing-dot name rules (8.3 also needs a volume that makes 8.3 names) |
| LLR-172.5g | `"TEMP"`, `"temp::$INDEX_ALLOCATION"`, `"TEMPLA~1"`, `"temp."`, `"AB"` | same |
| LLR-172.5h | the relative junction; the root-relative `\…` path | junction creation; Win32 root-relative paths |
| LLR-172.1b (G1) | `<d>\A.s19` then `<D>\a.S19` | `normcase` folds case only on Windows |

## Proposals
(appended to `interfaces-9a.md` §Proposals; rulings there: P-1 accepted then revoked by E3 R1, P-2 and P-3 accepted, P-4 accepted then superseded by E3 R3)
P-1 (S1). `record_recent_source` stores `str(path.resolve())` as `RecentEntry.path`. LLR-172.1a requires "the resolved absolute path"; G2 passes `normalized`, which can be a working-folder-relative spelling (`resolve_input_path` returns an existing relative candidate unchanged).
P-2 (S6). `record_recent_source` logs nothing at WARNING or above; the caller's one warning is the only one (LLR-172.1i "1 log warning").
P-3 (S9; numbered S8 at E2, renumbered by E3 R8). `recent_store_path()` reads `os.environ` when called, never at import (C8's autouse fixture depends on it).
P-4 (G2 consumers block, F-2). "`_handle_load_project`: reserved home (case-folded) refused before `_project_folder_refusal`" becomes "reserved home (`_is_reserved_home`: trailing dots and spaces stripped, then case-folded) refused before `_project_folder_refusal`". The typed-routing line gains "via `_typed_load_route`; a reserved name is refused there before any folder listing".
