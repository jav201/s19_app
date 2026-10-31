# Code-Wire baseline notes — Inc 9a slice at `4fef292`

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-9a.md` (this folder) |
| Nodes | 28: 19 in `app.py`, 2 in `screens.py` (`LoadFileScreen.on_button_pressed`, `LoadProjectScreen.compose`), 6 in `workspace.py` (`resolve_input_path`, `copy_into_workarea`, `contained_in_workarea`, `_is_reparse_point`, `validate_project_files`, `is_windows_device_name`), 1 in `utils.py` (`safe_text`). The `screens.py`, `workspace.py` and `utils.py` nodes are unchanged context, marked so the extractor lists their callers. |
| Nodes that 9a changes (per `func:`) | 5: `S19TuiApp._load_path_from_user_input`, `S19TuiApp.load_from_path`, `S19TuiApp.load_a2l_from_path`, `S19TuiApp.refresh_files`, `S19TuiApp._handle_load_project`. Conditional on a design decision: `S19TuiApp._start_load_worker` / `S19TuiApp._apply_prepared_load` (C1, the record point), `S19TuiApp.list_projects` / `S19TuiApp._project_folder_refusal` (C4, the one project predicate). |
| Target functions with no code | 4, all NEW in `workspace.py`: `recent_store_path` and `record_recent_source` (LLR-172.1), `read_recent_sources` (LLR-172.2), `list_workarea_files` (LLR-172.4). Not nodes: a baseline graphs code that exists. No recent or history store exists at `4fef292` (`grep -i "recent_source\|LOCALAPPDATA\|APPDATA"` over `s19_app/` and `tests/`: 0 product hits). |
| Example lines | 59 (24 marked "target (9a)"), each naming an AT / TC / LLR id, a premise (P-15, P-24, S-01, S-06, S-16), an existing test or a probe step |
| Entities | 4: `[I/O: workarea temp]` (with the load sequence showing success known only after the worker), `[I/O: project folder]`, `[Data: S19TuiApp.current_a2l_path]`, `[Data: S19TuiApp.current_project_dir]` |
| Marks written | 28, 0 nodes without code (throwaway detached worktree at `4fef292`, removed after the run; the b100-inc9a worktree's source untouched: `git status` shows only `.dev-flow/…/inc-9a/`) |
| Extractor | exit 0 at the first run, 0 findings, 43 real calls, 0 parse failures (Anaconda Python 3.12) |
| Lint (parse check only, not a gate) | 28 nodes, 4 entities, 0 lines not read |
| Report | `extract-baseline/diff-report.md`, `extract-baseline/extract.json` |
| Probe | `probe-p9a.py` (this folder), run once on `4fef292` with the s19env interpreter, `python -I`, the worktree first on `sys.path` (import line printed: `s19_app-b100-inc9a\s19_app\__init__.py`); output below |

Line numbers in the extractor report come from the marked copy. Subtract the marks above a site in the same file to get the `4fef292` line (for example, `app.py` sites after `refresh_files` are shifted by 2 or more). Line numbers in these notes are `4fef292` lines.

### Probe p9a output (executed, `4fef292`)

```text
== U1 list_projects ['ab', 'E']
== U2 validate_project_files(temp) ['firmware.s19']
== U3 typed <base>\.s19tool\workarea\ab -> ['Unsupported file type: '] project= None
== U3 typed <base>\.s19tool\workarea\ab\project.json -> ['Unsupported file type: .json'] project= None
== U3 typed ab -> ['File not found: ab'] project= None
== U3 typed temp -> ['File not found: temp'] project= None
== U4 _handle_load_project('temp') -> ["Loaded project 'temp' -> firmware.s19 - variant 1 of 1, 1 problem - details: p"] project= temp dir_has_project_json= False
== U5 _handle_load_project('TEMP') -> ["Loaded project 'TEMP' -> firmware.s19 - variant 1 of 1, 1 problem - details: p"] project= TEMP
== U6 _handle_load_project('E') -> ["Project NOT loaded: 'E' has no project.json — load a file and Save project."]
```

Setup: `ab` holds `firmware.s19` and `project.json`; `E` is empty; `temp` holds `firmware.s19`; the working directory is the base folder. P-15 and S-01 are re-executed here on `4fef292` (both cited at `1d677ba`): both still hold.

## Callers outside the slice that matter for 9a

1. **`resolve_input_path` has 5 callers outside the Load path** (`app.py:5383` `on_report_viewer_screen_filter_path_typed`, `:6577-6578` `_diff_sources_identical`, `:9450` Save project's parent folder, plus `changes/io.py:419`, `crc_designer_view.py:1307`, `operations/crc_config.py:361`, `operations/crc_designer_model.py:920`, `services/compare_service.py:528`). Adding a work-area base or a folder rule inside it changes the report filter, the A/B compare, the CRC designer and the Save parent. The typed-project step belongs in `_load_path_from_user_input`, not in `resolve_input_path` (C2).
2. **`_load_path_from_user_input` has 2 callers:** `_handle_load_dialog` (the dialog, `app.py:12765`) and `on_mount` (the command-line `load_path`, `app.py:7226`). The 9a project route therefore also runs on a startup path: a project folder given on the command line will open the project. Not stated in HLR-172; harmless, but a test that starts the app with a `load_path` sees it.
3. **`load_from_path` has 2 callers:** the router and `_handle_select_variant` (`app.py:7606`, a path inside the open project). The record must skip the variant switch by the "outside the work area" test, not by caller.
4. **`load_a2l_from_path` has 2 callers:** the router and `_load_from_item` (`app.py:13089`, a path inside `workarea/temp`, which copies onto itself through the byte-identical reuse). Same rule: inside → no record. (`_jump_to_section`, a caller at `ebe6d0c`, no longer calls it.)
5. **`refresh_files` has 5 callers:** `on_mount` (`:7193`), `action_refresh_files` (`:7322`, the `r` key), `_handle_save_dialog` (`:10596`), `load_from_path` (`:12834`, deferred with `call_later`), `load_a2l_from_path` (`:12890`). Every one repaints through the new lister; no caller reads the list's labels — `_load_from_item` reads `item.data` (TC-B99-34).
6. **`_handle_load_project` still has one production caller,** `_route_load_project` (`app.py:7473`); `action_load_project` is also reached from the Workspace button `ws_load_project_button` (`app.py:17391`). The typed project route is the second caller 9a adds (C3).
7. **`validate_project_files` has readers outside the slice:** the two project syncs (`_sync_loaded_file_to_project` `:12525`, `_sync_loaded_a2l_to_project` `:12590` / `:12698`), Save project (`:9915`, `:10102`, `:10903`) and `execute_project_variants` (`variant_execution_service.py:2743`). It accepts `temp` (probe U2). 9a should not put the reserved-home test into it: those readers act on the open project's folder, which a fixed `_handle_load_project` can no longer make `temp`.
8. **`copy_into_workarea` callers outside the slice** (`operations/crc.py:1507`, `flow_execution_service.py:1108`, `flow_persistence_service.py:1106`, two prototypes) are unaffected: the store is written outside every work area and must not go through the placement function, whose containment guard would refuse it anyway.
9. **Scripts outside `tests/` that drive the load:** `tools/e13/run.py:117` (`on_mount`) and `docs/images/capture_readme_media.py:88` (`_apply_prepared_load`). The LLR-172.1 autouse fixture in `tests/conftest.py` does not cover them: once 9a records, running either script writes to the real `%LOCALAPPDATA%\s19_app\recent_sources.json`.
10. **Calls the extractor cannot see** (name-based resolution): `_start_load_worker` hands `_apply_prepared_load` and `_handle_load_error` to `call_from_thread` as values, so the report shows no edge worker → install / error. The `_handle_load_project → _apply_prepared_load` and `→ is_windows_device_name` edges are lifts through unmarked helpers (`load_selected_file`; the variant-execution import), not direct calls. `LoadFileScreen.on_button_pressed` and `LoadProjectScreen.compose` are framework-called (0 callers listed).

## Listers of the work area at `4fef292`

| Where | What it enumerates | Its test |
|---|---|---|
| `refresh_files` (`app.py:7313`) | `workarea/temp/*`, `is_file()` (follows a file link) | none: every file that is not a folder |
| `list_projects` (`app.py:12080`) | `workarea/*` | not reserved (case-folded), `_project_folder_refusal` passes, `is_dir()`; no content check |
| `_handle_save_dialog` clash scan (`app.py:9559`, `:9574`) | `workarea/*`, then the matching folder's children | `project.json` is a file, or a child with a data or A2L suffix; not reserved; not a reparse point |
| `_assignment_candidate_files` (`app.py:7429`) | `current_project_dir/*.json` | a project folder, not the work area; out of scope |

TC-B100-37's census counts enumerations of `temp/`: at `4fef292` there is exactly 1 (`refresh_files`). `segment_split_view.py:877` builds a `temp/.staging` path for a length check and `action_dump_a2l_json` (`app.py:7693`) writes into `temp/`; neither enumerates. The census is therefore `1` on base and stays `1` after 9a (the enumeration moves to `list_workarea_files`); only its mutation arm can be RED.

## Candidates seen while reading (not findings unless marked executed)

- **C1 — where "loaded successfully" is.** `load_from_path` returns after `copy_into_workarea` and `_start_load_worker(copied)`; the parse runs in a thread worker and a failure arrives later through `_handle_load_error`. LLR-172.1 says "after a successful copy"; HLR-172 and LLR-172.1's threshold say "a failed load → 0 entries". A record right after the copy writes an entry for a file that then fails to parse. A record at `_apply_prepared_load` (the only point a data load is known to succeed) needs the source path, but the worker and the install receive only the work copy in `workarea/temp`. Options for E2: thread the source path through `_start_load_worker` → `_apply_prepared_load`; or define "successful" as "copied" and change the threshold. `load_a2l_from_path` is synchronous: its record can follow the parse in the same function. Also `_pending_variant_id`, `call_from_thread` ordering and the `exclusive=True` worker group (a second load cancels the first: the cancelled first must record nothing).
- **C2 — the typed path's resolution rule.** (executed, probe U3) `resolve_input_path` tries the working directory, the base folder and the repository root, never the work area, so the bare names `ab` and `temp` give "File not found". TC-B100-38's `ab` arm needs either a work-area base for a bare name or a full path in the test; the `temp`, `TEMP`, `patches` arms typed as bare names are already "0 project loads" on base, so they are not RED unless they type the work-area path (the RED side of S-01 is `_handle_load_project('temp')`, probe U4). Second part, not run: LLR-172.5 says "shall resolve the typed path", while LLR-171.4 checks links "before `resolve()`". `Path.resolve()` on `workarea/evil` (a junction to `workarea/R`) returns `workarea/R`, so a resolve-first router would load project `R` under the name `evil`'s pick — no containment breach, but the wrong project and no "link or junction" refusal. The router needs a lexical normalisation (`os.path.normpath` / `abspath`) for `..`, then `_project_folder_refusal` on the unresolved child, then containment. `_project_folder_refusal` already refuses a parent that is not textually the work area, so `workarea/x/../ab` must be normalised before it is called.
- **C3 — which project seam the typed path calls.** `_route_load_project` opens the Load-result panel (LLR-178.3); `_handle_load_project` alone does not. A typed project path that loads silently, while the picked one opens the panel, splits one action into two outcomes. LLR-172.5 says "load that project" without naming the seam; AT-B100-12 reads only the status log. LLR-173.1 (9b) routes `project` to `_handle_load_project` through one router; 9a should pick the seam 9b will keep.
- **C4 — three definitions of "a project", and LLR-172.5 cites the one that lacks a content test.** (executed, probes U1 / U6) `list_projects` lists an empty folder `E`; `_handle_load_project('E')` refuses it with "has no project.json" before the reset; the Save clash scan uses the §1.3 definition (holds `project.json`, a data file or an A2L). LLR-172.5: "`_handle_load_project` shall refuse any name that `list_projects` would not list (a reserved home …, a link, a non-project)". Read literally, `list_projects` would list `E`, so "a non-project" is not something `list_projects` filters today. Two designs: (a) one predicate (reserved + link/containment + content) used by `list_projects`, `_handle_load_project` and the typed router — TC-B99-35 then fails as written, because its `P1` / `P2` are empty folders (test fixture change owed); (b) keep `list_projects` and add only the reserved-home test to `_handle_load_project` (the content refusal already exists, U6) — smaller, one source file. Adding the reserved test inside `_project_folder_refusal` also reaches the Save target and save-as source, which already refuse reserved names earlier: harmless but a wider change than LLR-172.5 asks.
- **C5 — the Workarea Files pick and the safe label.** After LLR-172.6, the painted label of a name holding U+009B differs from the file name. `_load_from_item` reads `item.data` (the raw name), so the pick still loads the right file; any test or later code that matches rows by painted text would not. 9b's LLR-173.3 sink (`LoadProjectScreen.compose`, `screens.py:712`, a second `Label(name)` with markup on) stays open after 9a.
- **C6 — `.srec` and `.ihex` against the store's `kind`.** `S19_EXTENSIONS = {".s19", ".srec"}`, `HEX_EXTENSIONS = {".hex", ".ihex"}` (`workspace.py:107-108`). LLR-172.2 keeps an entry only when `kind` "matches the path's suffix"; LLR-172.1 does not say which kind `firmware.srec` is written with. Without one mapping table shared by the writer and the reader, a `.srec` load can be written and then dropped on read.
- **C7 — non-loadable files in the Workarea Files list.** `action_dump_a2l_json` writes `<stem>.a2l.json` into `temp/`; the list shows it and a pick routes it to `load_selected_file` → "Unsupported file type: .json". Pre-existing, by reading the code, not run. LLR-172.4 filters links and `.staging` only; the lister could take the suffix sets, or the requirement keeps today's behaviour. Not a 9a defect unless E1 decides the list shows loadable files only.
- **C8 — the startup path and helper scripts write recents.** See callers 2 and 9: once 9a records, a command-line load records it (correct by HLR-172's words) and two repository scripts outside `tests/` write the real per-user store. Low impact; worth one line in the design so a reviewer does not find it later.

## Requirement-text notes for E1 (not edited here)

- **Stale line citations** (cited → `4fef292`): `_load_path_from_user_input` `app.py:8658` → `:12715`; `load_from_path` `:8710` → `:12767`; `load_a2l_from_path` `:8789` → `:12846`; `refresh_files` `app.py:6543` → `:7300`; `Label(item.name)` `app.py:6559` → `:7316`; `list_projects` `app.py:8519` → `:12057`; `_handle_save_dialog` `app.py:8087` → `:9442`; `screens.py:707` `ListItem(Label(name))` → `:712`; `RESERVED_WORKAREA_HOMES` `workspace.py:40` → `:43`; the log lines `app.py:10820-10825` (§6.3) were not re-located. `utils.py:44` (`safe_text`) is correct.
- **"After a successful copy" vs "loads successfully"** (LLR-172.1 vs HLR-172 and LLR-172.1's "a failed load → 0 entries") — see C1.
- **"Shall resolve the typed path"** (LLR-172.5) vs "before `resolve()`" (LLR-171.4) — see C2; also say what a bare name is resolved against.
- **"Any name that `list_projects` would not list … a non-project"** (LLR-172.5): `list_projects` lists empty folders at `4fef292` — see C4; name the predicate or the change to `list_projects` (and TC-B99-35).
- **TC-B100-38's reserved arms** must type a path that reaches the work area (`<workarea>/temp`), else they pass on base for the wrong reason (C2, probe U3).
- **The kind of `.srec` / `.ihex`** (LLR-172.1 / 172.2) — see C6.
- **HLR-172 "the Workarea Files list and the Load dialog shall enumerate … through one function":** at 9a the Load dialog has no list (US-163, 9b); the 9a arm is the Workarea Files list only.
- **HLR-172 negative control** cites `1d677ba`; probe p9a re-executed P-15 and S-01 on `4fef292`: both hold (RED side intact).

## Wall time

About 8 min by the shell clock from the first read (01:43:46) to the extractor run and worktree removal (01:49:46), plus the notes; reading the requirements and the code and the one probe were most of it.
