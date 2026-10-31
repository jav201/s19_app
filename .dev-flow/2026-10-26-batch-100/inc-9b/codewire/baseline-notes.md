# Code-Wire baseline notes — Inc 9b slice on the 9a tree

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-9b.md` (this folder) |
| Base | the 9a tree (`C:\Users\jjgh8\Github\s19_app-b100-inc9a`): `4fef292` plus 9a's uncommitted changes to `app.py` and `workspace.py`. sha256 prefixes: `app.py` bbf04117fbf0, `screens.py` 49d6efdc73e2, `styles.tcss` 781f04ed2cc3, `workspace.py` 0af4b9248923. The worktree was only read; nothing was written there. |
| Nodes | 34. `screens.py` 5 (`LoadFileScreen.compose`, `.on_button_pressed`; `LoadProjectScreen.__init__`, `.compose`, `.on_button_pressed`). `app.py` 21: the slice (`action_load_file`, `action_load_project`, `_handle_load_dialog`, `list_projects`, `load_from_path`, `load_a2l_from_path`, `_load_from_item`, `check_action`), the named context (`_typed_load_route`, `_handle_load_project`, `_route_load_project`, `_load_path_from_user_input`, `_build_palette_entries`, `refresh_files`, `choose_install_set`), plus `_project_folder_refusal`, `_parse_loaded_file` (LLR-173.6b's MAC carry), and 4 caller-only nodes (`on_mount`, `on_button_pressed`, `on_list_view_selected`, `_handle_select_variant`) so that the extractor lists them as callers. `workspace.py` 6 (`resolve_input_path`, `record_recent_source`, `read_recent_sources`, `recent_kind`, `list_workarea_files`, `validate_project_files`). `project_gather_service.py` 1 (`painted_names`). `utils.py` 1 (`safe_text`). |
| Nodes 9b changes or retires (per `func:`) | 5 retired (the two screens' 5 methods). 8 changed: `action_load_file`, `action_load_project`, `_handle_load_dialog`, `list_projects` (Q7), `load_from_path`, `load_a2l_from_path` (CR9-1), `check_action` (S-g), `_load_from_item` (only if guess node G1 shares its body). All other nodes are unchanged context. `BINDINGS` is data: it is an entity, not a node. With Q8, 9b leaves it unchanged. |
| NEW nodes with no code | S1–S9 (`LoadChoice`, `LoadDialog.*`) and N1–N5, G1–G3 from E1-scope §3. A baseline graphs only code that exists, so these are not nodes here. |
| Example lines | 58, with 1 to 3 per node. Each names a probe step (p9b U1–U8 / F1–F9, p9a U1–U3 / U6), an existing test, or a code read. All describe behaviour that holds on the 9a tree. Where 9b turns a line RED, the line says so ("RED side of …", "after Q7: …"). |
| Caller lines | one `> callers (extractor): …` note after each node, generated from `extract-baseline/extract.json` and converted to 9a-tree line numbers (the extractor reports lines of the marked copy). "direct" means the site is inside the caller's own `def`; "through an unmarked helper" means the extractor lifted the call through a function that is not a node. "unmarked sites" lists call sites that have no marked node above them. |
| Extractor | `codewire_extract.py` (Code-Wire v3.1 core), Anaconda Python 3.12, on a throwaway marked copy. Exit 0: 34 marks, 34 graph nodes, 44 real calls, 0 findings, 0 ambiguous resolutions, 0 parse failures. The first run reported 1 drift: `LoadProjectScreen.__init__` had `out: None` in the graph, but a constructor node takes its class. I fixed the graph and re-ran. |
| Marks | 34 marks written by `codewire_marks.py` into `scratchpad/inc-9b-design/work/marked`, a copy of `s19_app/` committed into a throwaway `git init` repo, removed after the run. The worktree has 0 marks. |
| Lint | **Deviation:** I ran `codewire_lint.py` once as a parse check (34 nodes, 7 entities, 8 edges, 0 lines not read). The brief said to run no lint, so treat that run as unrequested. Nothing gated on it. |
| Report | `extract-baseline/diff-report.md`, `extract-baseline/extract.json` |
| Probe | `probe-p9b.py` (this folder). Output in `probe-p9b.out.txt`. It ran on a scratch copy of the 9a tree (`work/tree`, removed after the run) with the s19env interpreter (Python 3.11.15, Textual 8.2.8) and `python -I`, with the copy first on `sys.path`. The import line it printed is `…\inc-9b-design\work\tree\s19_app\__init__.py`. `LOCALAPPDATA` was pointed at a temp folder, so the real recent store was never touched. |

### Probe p9b output (executed, the 9a tree)

```text
== U1 p with 0 projects -> stack ['Screen'] status ['No saved projects found.']
== U2 list_projects ['[b]P', 'ab', 'c', 'E', 'j', 'n', 's']
== U3 _handle_load_project('E') -> ["Project NOT loaded: 'E' has no project.json — load a file and Save project."] project= None
== U3 _handle_load_project('n') -> ["Project NOT loaded: 'n' has no project.json — load a file and Save project."] project= None
== U3 _handle_load_project('j') -> ["Project NOT loaded: 'j' has no data or A2L file — load a file and Save project."] project= None
== U4 typed <workarea>/E -> ["Project NOT loaded: '<workarea>\\E' is not a project — pick a project in the list."]
== U5 p -> stack ['Screen', 'LoadProjectScreen'] focused project_list index 0 rows 7
== U5 painted labels ['P', 'ab', 'c', 'E', 'j', 'n', 's']
== U5 '[b]P' label renders 'P' type Content spans [(0, 1, 'b')]
== U6 escape on LoadProjectScreen -> stack ['Screen', 'LoadProjectScreen']
== U6 down -> index 1 focused project_list
== U7 enter on list -> stack ['Screen', 'LoadProjectScreen'] status [] project= None
== U8 project_ok on index 0 -> stack ['Screen', 'LoadResultScreen'] status ["Loaded project '[b]P' -> firmware.s19 - variant 1 of 1, 1 problem - details: p"] project= [b]P
== F1 l -> stack ['Screen', 'LoadFileScreen'] focused load_path
== F2 escape on LoadFileScreen -> stack ['Screen', 'LoadFileScreen']
== F3 empty Load click -> stack ['Screen', 'LoadFileScreen'] status []
== F4 Enter with a typed path -> stack ['Screen', 'LoadFileScreen'] current_file None
== F5 ctrl+l under LoadFileScreen -> actions run ['load_file'] stack ['Screen', 'LoadFileScreen', 'LoadFileScreen']
== F5 ctrl+s under LoadFileScreen -> actions run ['save_project'] stack ['Screen', 'LoadFileScreen', 'SaveProjectScreen']
== F5 ctrl+k under LoadFileScreen -> actions run ['focus_palette'] stack ['Screen', 'LoadFileScreen']
== F5 ctrl+d under LoadFileScreen -> actions run ['cycle_density'] stack ['Screen', 'LoadFileScreen']
== F5 density classes before/after ['density-comfortable'] ['density-compact']
== F6 typed relative R\x.s19 (cwd elsewhere) -> status ['Loaded x.s19']
== F6 store [('<base>\\R\\x.s19', 's19')] None
== F7 _load_from_item('w.s19') -> copy_into_workarea calls [] status []
== F7 _load_from_item('w.a2l') -> copy_into_workarea calls ['w.a2l'] status ['A2L loaded: w.a2l']
== F7 _load_from_item('w.a2l.json') -> copy_into_workarea calls [] status ['Unsupported file type: .json']
== F8 list_workarea_files ['w.a2l', 'w.a2l.json', 'w.s19', 'x.s19']
== F9 store after picks 1
```

(Paths are shortened to `<workarea>` / `<base>`; the stack "before" and focus columns of F5 are dropped here, see the `.out.txt`.)

Premises re-executed on the 9a tree. These were cited at `1d677ba` and still hold:
- P-18: escape on both screens, F2 and U6.
- P-19: an empty Load, F3, and Enter with a typed path, F4.
- P-20: no list in the Load file dialog, by code read of `LoadFileScreen.compose`.
- CR9-1: F6.
- LLR-173.2e's `planned` control is now **executed** (F5): all 4 priority actions run under the modal.

## Reverse census for ruling Q7 (§1.3 in `list_projects`, LLR-173.4a)

**Result:**
- **5 tests break:** each lists or loads a folder without content, and each fails once `list_projects` applies the §1.3 test.
- **21 test runs** (5 test functions) list a non-project folder as a bystander and pass unchanged.
- **1 requirement conflicts:** LLR-171.2e, see Surprise 1.

**Method (executed, not a reading):**
1. A throwaway pytest plugin (`work/plug/census_plugin.py`) wraps `S19TuiApp.list_projects` and `_handle_load_project` at runtime. The source is not edited.
2. **Run A (recorder):** for every call, the plugin logs each listed folder that fails §1.3, plus every project load of such a folder with the status lines it painted. §1.3 is spelled as `_typed_load_route`'s tail spells it: a regular, non-link `project.json`, or `validate_project_files` returns data, A2L or an error.
3. **Run B (the Q7 mutant):** the same wrapper, but `list_projects` drops those folders. It ran on the 26 test ids that run A recorded.
4. **Evidence in `work/`:**
   - Kept:
     - run A's records, `census-A.jsonl` (29 events);
     - the shard outputs `pytest-A0…A5.txt` and `pytest-X0…X4.txt`;
     - the test ids, `census-ids.txt`.
   - **Not kept:** run B's console output was deleted during cleanup. Its summary ("5 failed, 21 passed") and its assertion lines are transcribed in the tables below.
   - An earlier 2-process run on the same files was stopped as too slow; its stray pytest processes were found and stopped.

**Reach:**
- Run A covered the 47 test files that name a project-load entry point. The grep tokens were `list_projects`, `load_project`, `_handle_load_project`, `_route_load_project`, `LoadProjectScreen`, `project_list` / `project_ok`, `_typed_load_route`, `_load_path_from_user_input`, `_handle_load_dialog`, `load_path=`, `press("p")`, `ws_load_project_button`, `LoadFileScreen`, `load_ok`.
- It also covered the 5 further files that import the project helpers (`b97_fixtures`, `support/b100_projects`), shown in the extra table below.
- A test that reaches `list_projects` without any of those tokens or helpers is outside the census.
- Run A results:
  - The 6 shards gave 1,749 passed, 9 failed, 1 xfailed and 4 skipped, plus 12 errors.
  - The 12 errors are all in `test_id_registry.py`, which needs `.dev-flow/`; that folder was not copied to scratch.
  - The 9 failures: 2 palette / bindings goldens, 1 perf bound, `tc024` (a known flake), 1 A2B report byte-identity, 1 dwell timing, and 3 `tc_b100_61` folder-ceiling cases. All ran under 6 parallel shards on a loaded machine.
  - **Not triaged further.** None of them recorded a census event.

### Tests that break (run B: 5 failed)

| # | Test (file:line of the def) | Folder without content (file:line) | Today (run A) | Once `list_projects` applies §1.3 (run B) |
|---|---|---|---|---|
| 1 | `tests/test_tui_app.py:367` `test_list_projects_skips_files_and_sorts_names` | `Zulu`, `Alpha`, both empty (`:370`, `:371`) | `["Alpha", "Zulu"]` | `[]`; the assert at `:377` fails. To keep the test's intent (files skipped, names sorted), give both folders a `project.json`. |
| 2 | `tests/test_tui_helpers.py:132` `test_list_projects_ignores_temp` | `ProjectA`, `ProjectB`, both empty (`:136`, `:137`) | `["ProjectA", "ProjectB"]` | `[]`; the assert at `:143` fails. Same fix as row 1. |
| 3 | `tests/test_b99_load_project.py:154` `test_tc_b99_35_reserved_homes_are_not_projects` (TC-B99-35) | `P1`, `P2`, empty, next to every reserved home (`:160`–`:161`) | `["P1", "P2"]`, then `[]` after the rmtree | `[]`; the assert at `:163` fails. Its second half (`[]`) would then pass vacuously, because the reserved homes are empty folders too and the content test alone removes them. The fixture must give `P1` / `P2` content **and** give at least one reserved home content (for example `templates/t.s19`), else TC-B99-35 cannot tell the reserved rule from the content rule. 9a probe C4(a) already flagged this fixture. |
| 4 | `tests/test_tui_directionb.py:9072` `test_ac7_workspace_load_project_button` | `demo_project`, empty (`:9084`) | button → `LoadProjectScreen` pushed | `list_projects()` returns `[]`, so the status is "No saved projects found." and no dialog opens. The assert at `:9099` fails. At 9b the test is re-pinned anyway (`LoadProjectScreen` is retired, Q9). LLR-173.2a opens `LoadDialog` with 0 projects too, so a re-pin to `isinstance(app.screen, LoadDialog)` passes with or without content. The empty folder is then simply no row. |
| 5 | `tests/test_b100_project_homes.py:1016` `test_tc_b100_32_empty_folder_is_refused_before_any_reset[no project.json]` (TC-B100-32, LLR-171.2e) | `E`, empty (`:1031`), loaded by name through `_handle_load_project` (`:900`) | "Project NOT loaded: 'E' has no project.json — load a file and Save project." | "Project NOT loaded: 'E' is not a project — pick a project in the list."; the assert at `:1046` fails (it wants `no project.json` + `load a file and Save project`). Still 0 resets, and `N` stays open. **The requirement this test verifies (LLR-171.2e) becomes unreachable:** see Surprise 1. |

### Tests that list a non-project folder and pass unchanged (run B: 21 passed)

| Test | Folder (file:line) | Why it is unchanged |
|---|---|---|
| `tests/test_b100_recents.py:2307` `test_tc_b100_38_typed_folder_that_is_not_a_project_is_refused` (7 arms) | `empty` from `_reserved_fixture` (`:2281`) | A bystander in the listing. The `[empty]` arm types `<workarea>/empty` and expects `not a project` / `pick a project in the list`. Today that comes from the content tail of `_typed_load_route`; after Q7 it comes from the list match. The text is identical. |
| `tests/test_b100_recents.py:2460` `test_tc_b100_38_project_load_of_an_unlisted_name_is_refused` (6 arms) | `empty` (`:2281`) | A bystander. Every arm loads a reserved or unlisted name, which is refused the same way. |
| `tests/test_b100_recents.py:2605` `test_tc_b100_38_route_matches_the_typed_folder_against_the_listing` (4 arms) | `empty` (`:2281`) | A bystander. |
| `tests/test_b100_project_homes.py:1992` `test_e4_llr_171_1m_rebind_only_to_a_plan_entry[dot-dot]` | `elsewhere`, holding only `x.json` (`:2008`–`:2010`) | A bystander. It is never loaded. |
| `tests/test_b100_project_homes.py:2472` `test_tc_b100_31_rollback_never_deletes_through_a_swapped_folder` (3 arms) | `R`, holding only `reports/` (`:2435`–`:2436`) | A bystander. It is never loaded. |

### The 5 files that import the project helpers (run A: 0 census events)

`test_b97_check_editor.py` (36 passed), `test_b97_flow_builder.py` (67 passed, 2 skipped), `test_b97_key_bar.py` (38 passed), `test_b97_patch_editor.py` (38 passed), `test_b97_width.py` (145 passed). None of them lists or loads a folder without content: `b97_fixtures.make_project` always copies `prg.s19` into the folder.

## Selectors (`styles.tcss`, not graph nodes)

| Selector (line) | Current rule | Used by | 9b (E1 C1–C4) |
|---|---|---|---|
| `ModalScreen` (`:1576`) | `align: center middle`, dimmed base | every modal | unchanged |
| `.modal-dialog, #load_dialog` (`:1581`–`:1582`) | border, panel background, `padding: 1 2`, `width: 70%`, `height: auto` | the `Container`s of **5** screens. All 5 carry `id="load_dialog"`: `LoadFileScreen` (`screens.py:212`), `SaveProjectScreen` (`:607`), `LoadProjectScreen` (`:721`), `SaveFlowScreen` (`:778`), `LoadFlowScreen` (`:848`). 32 uses of `modal-dialog` in `screens.py`. | C1 "`#load_dialog` gets its own width": see Surprise 3 |
| `.modal-title` (`:1591`) | accent, bold | all modals | unchanged |
| `.modal-buttons` (`:1732`), `.modal-buttons Button` (`:1740`), `.modal-confirm` (`:1746`) | horizontal, docked bottom; confirm in the accent colour | `#loadfile_buttons`, `#loadproject_buttons`, other modals | `#load_buttons` can reuse them |
| `.modal-dialog Input` (`:1752`), `.modal-dialog Input:focus` (`:1758`) | border / focus border | `#load_path` | unchanged |
| `#project_list, #variant_list` (`:1762`) | border, base background, `height: 10` | `LoadProjectScreen`, `SelectVariantScreen` (`screens.py:991`) | C2: drop `#project_list`; keep `#variant_list` |
| `#load_panes`, `#load_left`, `#load_list`, `#load_preview`, `#load_reason`, `#load_buttons` | none yet | none | C3 / C4, new |

## Surprises

1. **Q7 makes LLR-171.2e unreachable, and the 9b draft does not say so.**
   - LLR-171.2e (Inc 8b, TC-B100-32): "a folder … with no `project.json` and neither a data file nor an A2L file → refuse with the `no project.json` tokens".
   - After Q7 such a folder is never listed. So `_handle_load_project` refuses it at the list match, with `is not a project` / `pick a project in the list`, before the `has no project.json` branch.
   - That branch becomes dead code: every folder that is listed has a manifest, a data file or an A2L. A manifest-only folder still reaches the `has no data or A2L file` branch.
   - Census row 5 is the visible break. `E1-requirements-draft.md` never cites LLR-171.2e.
   - E1/E3 must either retire LLR-171.2e (with its token-table row "Load: no `project.json` …", `01-requirements.md:371`) or amend it to the `not a project` tokens.
2. **An A2L Workarea Files pick copies once.**
   - `_load_from_item` → `load_a2l_from_path` → `copy_into_workarea` onto itself (p9b F7: 1 call for `w.a2l`, 0 for `w.s19`).
   - LLR-173.1b's threshold says "0 `copy_into_workarea` calls" for a `workarea` choice. If guess node G1 shares `_load_from_item`'s body, the A2L arm makes 1 call.
   - Either the threshold names data files only, or the `workarea` A2L arm needs an in-place A2L load. That function does not exist: `load_a2l_from_path` always copies.
3. **`#load_dialog` is the id of 5 modals, not 1.** C1's "`#load_dialog` gets its own width (two panes)" would also widen Save project, Save flow and Load flow. Either the new dialog takes a new id, or the rule is scoped (for example `LoadDialog #load_dialog`). This collides with the VS-PA-3 id list, which names `#load_dialog`.
4. **All 4 priority keys act under the modal today** (p9b F5, LLR-173.2e executed, 4 of 4):
   - `ctrl+l` stacks a second `LoadFileScreen`;
   - `ctrl+s` stacks `SaveProjectScreen` over the Load dialog;
   - `ctrl+d` changes the density behind it.

   `check_action` has no modal test. It is also read by the key bar (`window_help.py:1134` / `:1145`, `KeyRow` via `_app_check`). So the S-g guard dims those 4 keys in the main screen's key bar while `LoadDialog` is open, wherever that bar repaints. The dialog snapshots (Q8 → Inc 12a) may show it.
5. **Enter in `#project_list` does nothing today** (p9b U7): `ListView.Selected` has no `project_list` arm, and only `#project_ok` loads. Today's dialog has no "Enter loads" path to keep. HLR-173c's list arm is entirely new.
6. **LLR-173.6b's MAC carry is in `_parse_loaded_file`, not `_apply_prepared_load`** (the E1 "Live semantics" item).
   - A data-file load keeps the current file's MAC (`_merge_primary_with_existing_mac`).
   - It keeps its A2L when the new primary has none.
   - A MAC load overlays the MAC onto the current S19/HEX.
   - The merge reads `self.current_file` in the worker thread at parse time. The install only applies the merged result.
7. **CR9-1 detection needs no new input.**
   - `resolve_input_path` returns the candidate unresolved when it exists as typed, and `(base|repo) / candidate` resolved when only a fallback hit.
   - `record_recent_source` has no "how found" parameter.
   - The caller (`load_from_path` / `load_a2l_from_path`) can tell the fallback by "typed text is relative and does not exist from the working directory". That is a reading, not a design.
8. **`list_projects` sort order:**
   - On Windows, `sorted(Path)` is case-insensitive: `['[b]P', 'ab', 'c', 'E', 'j', 'n', 's']`.
   - On Linux CI the same folders sort case-sensitively (`E` first).
   - A 9b test that pins the projects section's row order on both platforms must not assume one or the other.

## Callers outside the slice that matter for 9b

- **`list_projects` callers:**
  - 3 direct product callers (`action_load_project`, `_handle_load_project`, `_typed_load_route`).
  - No unmarked product call site.
  - The Save clash scan enumerates the work area by itself (`app.py:9559` / `:9574` in 9a numbering) and does not call it.
  - Q7 therefore changes the Load list, the pick match and the typed match, and nothing else.
- **`_project_folder_refusal`** has 2 unmarked sites in `_handle_save_dialog` (`app.py:9647`, `:9694`). Q7 does not touch it.
- **`resolve_input_path`** has 9 unmarked sites (report filter, A/B compare, Save parent, CRC designer and others; see the 9a notes, caller 1). LLR-172.1n must stay in the two load functions and not move into `resolve_input_path`.
- **`refresh_files`** also runs from `action_refresh_files` (`:7327`) and `_handle_save_dialog` (`:10601`). The dialog's files section is a separate reader of `list_workarea_files` (N1), not of `#files_list`.
- **`check_action`:** `window_help.py:1134`, `:1145` (Surprise 4).
- **Calls the extractor cannot see** (name-based resolution):
  - `action_load_file` → `_handle_load_dialog` and `action_load_project` → `_route_load_project` (callbacks passed to `push_screen`);
  - `_handle_load_dialog` → `_load_path_from_user_input` (`call_after_refresh`);
  - the palette (`run_action` with a string).
  - The `_parse_loaded_file` edges are lifts through `load_selected_file` / `_start_load_worker`.
  - The screens' methods and the `on_*` handlers are called by the framework (0 callers listed).

## Wall time

About 75 minutes by the shell clock. The census took most of it: a first full-candidate run in 2 processes was too slow and was stopped. The shard runs then took 12–26 minutes each, in parallel. The probe, the graph and the extractor took about 20 minutes.
