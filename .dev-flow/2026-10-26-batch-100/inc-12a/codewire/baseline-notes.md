# Code-Wire baseline notes — Inc 12a slice on main 8947666 (designed post-9b / post-10 / post-11)

## Numbers

| Item | Value |
|---|---|
| Graph | `baseline-12a.md` (this folder) |
| Base | main checkout `<HOME>\Github\s19_app` at `8947666`, clean apart from the untracked `prototypes/load_projects/` that was there before. sha256 prefixes: `app.py` bbf04117fbf0 (the same bytes the 9b, 10 and 11 baselines read), `styles.tcss` 781f04ed2cc3, `workspace.py` 0af4b9248923. The checkout was only read. Probes and test runs used copies in `../work/tree` and `../work/mutant`. One test (`test_tc081_4_no_binding_diff`, it runs `git diff main`) ran on the checkout read-only, with `-p no:cacheprovider` and `PYTHONDONTWRITEBYTECODE=1`; `git status` was unchanged afterwards. |
| Nodes | **35**: `app.py` 31, `workspace.py` 2 (`recent_kind`, `list_workarea_files`), `project_gather_service.py` 1 (`painted_names`), plus the `app.py` count above includes 4 nodes with no code. G-A: `set_progress`, `set_file_status`, `set_status`, `compose`, `load_from_path` (post-9b), `_start_load_worker`, `_handle_load_error`, `_apply_prepared_load`, `load_selected_file`, `load_a2l_from_path` (post-9b), `action_before_after_report`, `_start_before_after_worker`, `on_report_viewer_screen_generate_requested` (caller only), `_trigger_generate_report`, `_start_generate_report_worker`, `_finish_generate_report`, `on_ab_diff_panel_report_requested`, `_start_diff_report_worker`, `_handle_load_project` (post-10), `_route_load_project` (post-10, caller only), `_handle_save_dialog` (post-11), `_commit_project_save` (post-11, no code). G-B: `_build_palette_entries`, `list_projects` (post-9b), `refresh_files`, `_typed_load_route` (post-9b), `_load_path_from_user_input` (post-10), `_load_from_item` (post-9b), `on_list_view_selected` (caller only), `_load_workarea_file` (post-10, no code), `_load_dialog_rows` (post-9b, no code), `_load_dialog_verdict` (post-9b, no code), `recent_kind`, `list_workarea_files`, `painted_names`. |
| Nodes 12a changes (per `func:`) | 23: G-A 18 (`set_file_status`, `load_from_path`, `_start_load_worker`, `_handle_load_error`, `load_a2l_from_path`, `action_before_after_report`, `_start_before_after_worker`, `_trigger_generate_report`, `_start_generate_report_worker`, `_finish_generate_report`, `on_ab_diff_panel_report_requested`, `_start_diff_report_worker`, `_handle_load_project`, `_commit_project_save`, plus `set_progress` (callers only, signature kept)); G-B 7 (`BINDINGS` data through `_build_palette_entries`, `list_projects`, `refresh_files`, `_typed_load_route`, `_load_path_from_user_input`, `_load_workarea_file`, and `_handle_load_project`'s listing block). The rest are context. |
| NEW nodes with no code | The seam `begin_busy`, `step_busy`, `end_busy`, `_busy_tick`, `_busy_line`, the table `_BUSY_ACTIONS`, the state `_BusyRun` / `_BusyState`, the helper `_busy_begin_action` (G-A); `_listed_project_name` (G-B). A baseline graphs only code that exists, so they are seams in `interfaces-12a-proposed.md`. E1 guess G2 (`_loadable_suffix`) is dropped: the predicate already exists as `recent_kind` (S-h). |
| Post-9b / post-10 / post-11 nodes | in code, body from the graphs: `load_from_path`, `load_a2l_from_path`, `list_projects`, `_typed_load_route`, `_load_from_item` (9b); `_load_path_from_user_input`, `_handle_load_project`, `_route_load_project` (10, with 9b inside); `_handle_save_dialog` (11). Not in code, not marked: `_load_workarea_file`, `_load_dialog_rows`, `_load_dialog_verdict`, `_commit_project_save`. |
| Example lines | 84, 1 to 5 per node. Each names a probe step (p12a U1.1 … U4.1, P12a-1 … P12a-4), an existing test, a code read, or a line of the 9b / 10 / 11 graphs. All hold on the base unless they say post-9b / post-10 / post-11. Where 12a turns a line RED, the line says so. |
| Caller lines | one `> callers (extractor): …` note per node, generated from `extract-baseline/extract.json` by `../work/callers.py` (`../work/callers.out.txt`) and converted to base line numbers (each base line = marked line minus the marks above it in the same file). "direct" means the site is inside the caller's own `def`; "through an unmarked helper" means the extractor lifted the call through a function that is not a node. Callables passed as values (`call_from_thread(self.set_progress, …)`, `call_from_thread(self._handle_load_error, …)`) are not calls to the extractor; their sites are listed from P12a-1 and a code read. |
| Extractor | `codewire_extract.py` (Code-Wire v3.1 core), s19env Python 3.11, on a throwaway marked copy. Exit 0: 31 marks, 31 graph nodes, 51 real calls, 0 findings, 0 ambiguous resolutions, 0 parse failures. The graph given to the extractor (`../work/graph-extract.md`) is `baseline-12a.md` minus the 4 nodes with no code. |
| Marks | 31 marks written by `codewire_marks.py` into `../work/marked`, a copy of `s19_app/` committed into a throwaway `git init` repo (`31 marks written, 0 nodes without code`). The checkout has 0 marks. |
| Lint | not run (brief: no lint, coherence or STE gates). |
| Report | `extract-baseline/diff-report.md`, `extract-baseline/extract.json` |
| Probe | `probe-p12a.py` (this folder); output `probe-p12a.out.txt`; stderr `probe-p12a.err.txt` (only the app's own logged tracebacks of the U2.2 / U2.3 parse of a folder). It ran on `../work/tree` (a copy of `s19_app/`, `tests/`, `tools/`, `examples/case_01_basic_valid`) with the s19env interpreter (Python 3.11, Textual 8.2.8), `python -I`, `PYTHONDONTWRITEBYTECODE=1`, `PYTHONUTF8=1`, `LOCALAPPDATA` in `../work/localappdata`, and temp folders under `../work/ptmp3`. The import line prints `…\inc-12a-design\work\tree\s19_app\__init__.py`. |

### Probe p12a output (executed, base; paths shortened)

```text
== U1.1 file_load success progress=[10, 50, 100] end_bar=100 status_text='Loaded firmware.s19 (S19 only)'
   log+ ['Copying into workarea temp...', 'Parsing firmware.s19...', 'Loaded firmware.s19 (S19 only)', 'Loaded firmware.s19']
== U1.2 file_load failure (parse raises -> _handle_load_error) progress=[10, 50, 100] end_bar=100
   log+ ['Copying into workarea temp...', 'Parsing firmware.s19...', 'Load failed: synthetic parse failure', 'Load failed']
== U1.3 file_load failure (copy refused) progress=[10, 0] end_bar=0
   log+ ['Copying into workarea temp...', 'Cannot load file: synthetic containment refusal']
== U1.4 a2l_load success progress=[10, 50, 100] end_bar=100 status_text='Ready.'
   log+ ['Copying A2L into workarea temp...', 'Parsing firmware.a2l...', 'Loaded firmware.a2l', 'A2L loaded: firmware.a2l']
== U1.5 a2l_load failure (parse raises) progress=[10, 50] end_bar=50 status_text='Ready.' exc=RuntimeError
   log+ ['Copying A2L into workarea temp...', 'Parsing firmware.a2l...']
== U1.6 project_load success progress=[] end_bar=0.0 status_text="Loaded project 'P' -> firmware.s19"
   log+ ['Loaded firmware.s19 (S19 only)', "Loaded project 'P' -> firmware.s19 - variant 1 of 1, 1 problem - details: p"]
== U1.7 project_load failure (manifest only: no data or A2L) progress=[] status_text unchanged
   log+ ["Project NOT loaded: 'Q' has no data or A2L file — load a file and Save project."]
== U1.8 B9 wa-files seed problems [('no digests saved', 'project.json', None)]
== U1.9 save_project success progress=[] end_bar=100 (left by the earlier load)
   log+ ['Project saved + manifest verified', 'Saved project to …\\S1 …']
== U1.10 save_project failure (placement OSError after mkdir) progress=[] exc=None
   log+ ['Project NOT saved: could not save — [Errno 28] synthetic no space. check the folder.']
   S2 exists after failure: False
== U1.11 report success progress=[15, 55, 100] end_bar=100
   log+ ['Report: no prior execution - running active scope...', "Executing variant 'a' (1 file(s))...", "Variant 'a': ok - 1 change, 0 check", 'Report: reports/<stamp>-report.md']
== U1.12 report failure (generator raises) progress=[15, 55, 0] end_bar=0
   log+ [... 'Report failed: RuntimeError: synthetic report failure']
== U1.13 diff_report success progress=[15, 55, 100] end_bar=100   log+ []
== U1.14 diff_report failure (markdown refused) progress=[15, 0] end_bar=0   log+ []
== U1.15 before_after refused (nothing loaded) progress=[15, 0] end_bar=0
   log+ ['Before/after report refused: No applied change summary - …']
== U1.16 before_after success (composer stubbed) progress=[15, 100] end_bar=100
   log+ ['Before/after report written: …']
== U2.1 refresh_files rows ['a.s19', 'b.hex', 'c.mac', 'd.a2l', 'd.a2l.json', 'e.txt']
== U2.2 pick folder fw.s19 -> parse calls ['fw.s19'] log+ ["Load failed: [Errno 13] Permission denied: '…\\temp\\fw.s19'"]
== U2.3 pick junction fw.s19 -> parse calls ['fw.s19'] log+ ["Load failed: [Errno 13] Permission denied: …"]
== U2.4 pick file symlink fw.s19 -> parse calls ['fw.s19'] current_file=…\workarea\temp\fw.s19
== U2.5 cap 1024: picks edge.s19 (1024 B) big.s19 (1025 B) -> parse calls ['edge.s19', 'big.s19']
== U2.6 _typed_load_route('fw\x00.s19') raises ValueError: stat: embedded null character in path
== U2.7 _load_path_from_user_input('fw\x00.s19') raises ValueError
== U2.6 _typed_load_route('<tmp>\\fw\x00.s19') -> ('refuse', 'not found')
== U2.7 _load_path_from_user_input('<tmp>\\fw\x00.s19') -> returned
== U2.8 list_projects with 'fw-v1.', 'fw-v2 ', 'P' on nt -> ['P']
== U3.1 palette load entries [('Load file', 'load_file'), ('Load project', 'load_project')]
== U3.2 bindings [('ctrl+l', 'load_file', 'Load file'), ('l', 'load_file', 'Load file'), ('p', 'load_project', 'Load project')]
== U3.3 timers attribute WeakSet count 0
== U3.4 status_line height 1 progress_bar Region(x=2, y=46, width=46, height=1) log_line_1 y 47
== U4.1 refusal literal sites (docstrings excluded): see probe-p12a.out.txt (13 functions)
```

Notes on the probe:
- U1.13 / U1.14 call `_start_diff_report_worker` directly after a `set_progress(15)` (what the request handler does), with both generators stubbed. Building a real comparison by keys was not needed for the bar and log trace.
- U1.15 / U1.16: the before/after refusal is decided inside the worker, after the kickoff, so it is a failure exit after the begin.
- U1.10: the Save failure exit rolls the folder back and raises nothing (the `OSError` arm), so it is a reachable failure after the begin.
- U2.4: the file symbolic link was made, so on this host LLR-172.6b arm (c) can run.

### Controls owed at E2 by the E1, now executed

| E1 item | Result on base |
|---|---|
| LLR-172.6b arms (a), (b) | (a) folder `fw.s19` and (b) junction `fw.s19` → `_parse_loaded_file` called on the entry (1 call each), `Load failed: [Errno 13] Permission denied` (U2.2, U2.3). Arm (c) file link → parsed and installed (U2.4). RED on all 3 arms. |
| LLR-172.6c | cap patched to 1 024: the 1 025-byte pick parses (U2.5). RED. |
| LLR-176.2c failure arms | one reachable failure exit after the begin per action: interfaces S-n table (file load U1.2, Save U1.10, report U1.12, diff report U1.14, before/after U1.15; A2L load and project load by code read). The bar ends at 100 after a failed file load (U1.2), and at 50 after a raising A2L parse (U1.5). |
| LLR-172.5k painting sites | AST, docstrings excluded (U4.1). Load path: `_load_path_from_user_input` `not a project` 2 (`:12949` the reason test, `:12950` the sentence), `could not be read` 1 (`:12963`); `_handle_load_project` `could not be read` sentence 2 (`:11694`, `:11716`), logger 1 (`:11722`), A2L reason word 1 (`:11762`), `not a project` sentence 1 (`:11733`, split over two literals, so not found by a substring test); `_typed_load_route` reason keys `not a project` 3 (`:12867`, `:12883`, `:12903`). Save path (out of scope, Q-7): `_handle_save_dialog` 3, `_plan_project_save` 1, `_unrecorded_document_lines` 1. |
| B9 (OBS-9a-2) | executed (U1.8): the E13 `wa-files` seed's `project.json` has no `files` key → `check_project_files` → 1 problem `no digests saved` on `project.json`. That is the "1 problem" of the scenario, by design. The E1 named it "present, not recorded"; the code calls it `no digests saved`. Close as not a defect. |
| LLR-172.5i | relative NUL text raises `ValueError` (U2.6, U2.7); the absolute NUL text is already refused `not found` (U2.6). 2 of the 4 arms are GREEN on base. |
| LLR-172.4e | Windows arm GREEN on base (U2.8); Linux arm RED (the `os.name` gate, P12a-4). |

## Selectors (`styles.tcss`, not graph nodes)

| Selector (line) | Current rule | 12a |
|---|---|---|
| `#workspace_status_bar` (`:539`) | `height: auto`, top rule, panel background | unchanged |
| `#status_line` (`:558`) | `height: 1; width: 100%` | unchanged (one row: the progress line is clipped, never wrapped) |
| `#workspace_status_bar #status_text` (`:572`) | `height: auto; color: $fg-base; width: 1fr; text-overflow: ellipsis` | unchanged; S-g adds `#workspace_status_bar #status_text.-busy { color: $accent-calm; }` (Q-6) |
| `#workspace_status_bar #status_context` (`:604`) | right-aligned, `max-width: 70%` | unchanged |
| `#progress_bar` (`:617`) | `margin-top: 1` | unchanged; nothing hides it (LLR-176.1s holds on base, U3.4) |

## Census

### Method

- Grep over `tests/` (file::test names below), plus the assertions read against the seams in `interfaces-12a-proposed.md`.
- Two executed runs:
  - a base run on `../work/tree` of the progress and label pins;
  - a mutant run (M1) on `../work/mutant` of the 16 test files that both run a file or A2L load and read the status log. M1 drops the begin and step messages from the log, the Q-3 option 1 effect. Its only change is `set_progress`'s `if message:` becoming `if message and value >= 100:`.
- Failures of M1 were re-run on the base copy to separate the mutant's effect from failures that are already there.

### A. Breaks through the indicator (G-A), by reading the assertion against S-a

| # | Test | Today (base) | After 12a | Disposition |
|---|---|---|---|---|
| A1 | `tests/test_report_progress.py::test_report_generation_drives_progress_bar_to_100` (:49) | bar 100 (passed, base run) | bar 0 (cleared at the end) | re-pin (E1 §D.3 already names it) |
| A2 | `tests/test_report_progress.py::test_kickoff_sets_bar_in_progress_before_worker` (:93) | bar 15, `0 < p < 100` (passed) | the begin writes 0 and the stubbed worker never steps → 0 | re-pin to "the progress line is painted" (**not in E1 §D.3**) |
| A3 | `tests/test_report_progress.py::test_finish_generate_report_completes_bar` (:118) | direct `_finish_generate_report(path)` → 100 (passed) | Q-1 option 1: `TypeError` (no `gen`); option 2: no run → bar stays 40 | re-pin: begin a run, end it, assert the cleared bar (**not in E1**) |
| A4 | `tests/test_before_after_report.py::test_at_038a_saveback_trigger_report_pair_reread_from_surfaced_path` (:271 `progress[-1] == 100`) | passed | spy ends 0 | re-pin (**not in E1**) |
| A5 | `tests/test_report_off_ui_thread.py::test_ac4_diff_progress_never_sticks_mid_fill` (success arm `[-1] == 100`) | passed | ends 0 | re-pin the success arm; the refused arm (`[-1] == 0`) holds (**not in E1**) |
| A6 | `tests/test_tui_report_attribution.py::test_at263_pin_progress_resets_to_zero_on_both_branches` | direct worker call, last value 0 (passed) | no begin → the seam writes nothing for it → empty list | re-pin: `_drive_worker` begins a `report` run first |
| A7 | `tests/test_tui_report_attribution.py::test_at260_…`, `::test_at261_…`, `::test_at262_…`, `::test_tc571_…` (all through `_drive_worker`) | passed | Q-1 option 1: `TypeError` until `_drive_worker` passes `gen`; option 2: pass (their result lines stay `set_status` calls under Q-3 option 1) | the same one helper edit as A6 |
| A8 | `tests/test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census` | passed | the new `self._busy =` is unclassified | add `_busy` to `SNAPSHOT_EXCLUSIONS` with its reason (S-b) |

Held, by reading:
- `test_report_progress.py::test_failed_report_resets_progress_bar_to_zero` (ends 0).
- `test_report_off_ui_thread.py::test_ac3_before_after_progress_never_sticks_mid_fill` (`[-1] in (0, 100)`).
- `test_tui_report_attribution.py::test_tc572_the_tool_failure_sequence_exists_exactly_once` (source counts; held only if G-A keeps `report_failed` as the single builder of `f"Report failed:`).
- `test_tui_variants.py` `_parse_loaded_file` call-site census (held if `_start_load_worker` keeps the call).
- `test_tui_directionb.py:2206` and `test_report_progress.py:126` call `set_progress` directly: allowed, since LLR-176.2a counts `app.py` only.

### B. Breaks through the labels (G-B, LLR-173.2m)

| # | Test | Today | After 12a | Disposition |
|---|---|---|---|---|
| B1 | `tests/test_b97_key_bar.py` `GLOBAL_TEXTS` (`^l Load file`) and `GLOBAL_TEXTS_80 = GLOBAL_TEXTS[:6]`, read by `test_tc_b97_67_row_one_is_the_eight_globals_whatever_the_focus` (:354), `test_tc_b97_67_row_one_at_80x24_drops_palette_whole` (:411), `test_at_b97_25_two_rows_on_every_window_and_clicks` (:1373), `test_tc_b97_70_every_painted_row_is_whole_tokens` (:1097, `known` set) | :354 and :411 passed in the base run | `^l Load`; row 1 at 80×24 is re-measured (the shorter label may let `q Quit` back) | re-pin `GLOBAL_TEXTS`, re-measure `GLOBAL_TEXTS_80` |
| B2 | `tests/test_tui_diff_screen.py::test_at_b78_32_app_bindings_block_is_untouched` | **RED on base** (base run): the frozen rows hold `('ctrl+l', 'load_file', 'Load', True)` and `('ctrl+s', 'save_project', 'Save', True)`; the code says `Load file` / `Save project` | `ctrl+l` row matches; `('l', …, 'Load file')` and `('p', …, 'Load project')` rows now differ; `ctrl+s` still differs | re-pin the `l`, `p`, `ctrl+s` rows; record that the test was red before 12a |
| B3 | `tests/test_tui_patch_history_strip.py::test_tc081_4_no_binding_diff` | passed (checkout, read-only) | the changed `Binding("l", …)` and `Binding("p", …)` lines are unsanctioned against `main` | add two sanctioned markers (as batch-97 did for `"ctrl+l", "load_file"`) |
| B4 | the 29 snapshot files `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[<cell>].svg` | re-counted on base: 29 hold `Load&#160;file` once; 6 workspace cells also hold the key row `p Load&#160;project`; 4 of those also paint the button `Load&#160;project&#160;(p)`, which stays | 35 label cells change | regenerate **only** through `.github/workflows/snapshot-regen.yml` (ubuntu-latest, Python 3.11, `pytest-textual-snapshot==1.1.0`), commit only the 29 files. A constraint to record, not run here. |

Not affected:
- `test_b97_key_bar.py::_layer0_lists` builds its own `("p", "Load project")` token list for a packing test (test-local input).
- The prose `Load files with ^L / l` in `window_help.py:314` is not a binding description.

Also failing in the base run, and not about labels: `test_b97_key_bar.py::test_tc_b97_69_page_keys_do_nothing_where_disabled`, `::test_tc_b97_69_dimmed_entries_follow_their_condition`, `::test_tc_b97_69_owned_keys_dim_outside_their_window`, `::test_tc_b97_72_clicks_run_the_action_and_type_nothing`, `::test_tc_b97_72_owner_click_runs_on_its_widget_not_the_focus`, `::test_tc_b97_72_confirm_click_with_the_focus_in_an_input`, `::test_at_b97_26_keys_only_help_and_hidden_view`. That run used a copy that held only `examples/case_01_basic_valid` (the other examples were copied later), and it ran beside the first mutant run. The failures are probably environmental. Not triaged and not re-run (coordinator: no further loops). They are E4's gate baseline, not 12a breaks.

### C. Breaks through the sweep (G-B)

| # | Test | After 12a | Disposition |
|---|---|---|---|
| C1 | `tests/test_b100_recents.py::test_tc_b100_38_project_list_keeps_a_trailing_dot_name_off_windows` (:2548) | it pins the CR9-9 platform scope ("lists it elsewhere"): `fw-v1.` in `off_windows` → no longer listed on any platform → RED on Windows (off-Windows half) and on Linux | re-pin: superseded by LLR-172.4e (**not in E1 §D.3**, which says "E2 derives it") |
| C2 | `refresh_files` rows | `tests/test_b100_recents.py` (TC-B100-39 hostile names, AT-B100-13): every listed name ends `.s19` → held. `test_tui_directionb.py::test_ac5_files_list_grows_beyond_legacy_cap`: measures height → held. No test lists a `.a2l.json` or `.txt` row in `#files_list` (grep). | none |
| C3 | `_load_from_item` picks (`test_b100_focus.py:364`, `test_b100_recents.py`, `test_b99_load_project.py`) | every pick is a regular, small `.s19` → held by S-i | none |
| C4 | NUL, one match, one wording | no test types a NUL; the refusal texts are unchanged character for character (S-k), so TC-B100-38 / -40 / -63 hold | none |

### D. The status log and `#status_text` (mutant M1, executed)

**Result: 0 failures traced to M1 (begin and step lines dropped from the log). This is partly executed and partly by grep, as stated per file below.**

**Grep (whole `tests/`):**
- 0 tests pin `Copying into workarea temp`, `Copying A2L into`, or a `Parsing <name>...` line.
- 0 tests pin `"Load failed"` as a whole line.
- The lines tests read after an action are the last log line (`log_lines[-1]`, 19 sites; `#log_line_4`, for example `test_b100_focus` reads `A2L loaded:` 8 times) or `#status_text`. Under S-d / Q-3 option 1, both keep today's text.

**M1 run, `../work/m1out2/` (16 files, `--basetemp` under `../work/pt-m3`):**
- 8 files fully green on the mutant:
  - `test_b100_focus` 34 passed;
  - `test_b100_reuse` 38;
  - `test_b99_a2l_encode` 7;
  - `test_b99_bytes_field` 3;
  - `test_b99_load_project` 4;
  - `test_b99_s0` 6;
  - `test_tui_operations_view` 5;
  - `test_tui_directionb` 184.
- 8 files with failures: `test_b100_active_variant` 18, `test_b100_project_check` 19, `test_b100_save_guards` 63, `test_b100_save_image` 53, `test_b99_editor_image` 1, `test_b99_export` 4, `test_b99_staging` 1, `test_tui_commandbar` 2.
- Every failure message read is environmental, not M1:
  - `Project NOT saved: path too long — shorten the name.` (the deep scratch `--basetemp` pushes the work area past the G9 limit; about 150 of the 161 lines);
  - `… resolves to 317 characters — over the platform limit of 260`;
  - `precondition: this run's tmp home must allow a 152-character home`;
  - a missing `AT-TC-REGISTRY.jsonl` (not copied);
  - the palette freeze `the pre-change palette action set must equal the Inc-0 freeze` (`test_tui_commandbar`, unrelated to the log).
  - None names a begin or step line.
- Distinct `E` lines: `../work/m1out2/test_*.txt`; the FAILED list: `../work/m1out2/_failed.txt`.

**Re-run with a short `--basetemp` (`../work/m1out3/`):**
- Started to clear the path-length artefact, and stopped at the coordinator's wrap-up call (no broad runs; the batch-end battery covers it).
- Result: `test_b100_active_variant` ran its first 26 tests on the mutant with 0 failures (the first run had 18 path-length failures in that file); the loop was then stopped, and no pytest process was left running.
- The rest of those 8 files is **by grep, not executed**: no assertion in them pins a begin or step line (grep above).

**Not executed: `#status_text` read while a worker action still runs.**
- By grep, not executed, with a reasoning rule: after the last end, `#status_text` holds the same text as today.
  - File load: the pending file state.
  - Project load: the final line.
  - A2L load, Save project and reports: `restore`, which equals today's untouched text.
- So only a read **between** begin and end changes. The file-load and report waits poll for the end state, which is reached after the end.
- 29 test files name `status_text`; the runtime census of reads inside a run is owed at E4 / the batch-end battery.

## Surprises

1. **E1 §D.3 under-counts the progress pins.** It names one re-pin (`test_report_progress.py:49`) and says the spies "still see every value". With a begin that writes 0 and a last end that clears to 0, 5 more tests turn RED (census A2–A6), plus up to 4 through `_drive_worker` (A7, depending on Q-1), plus TC-B100-09 (A8).
2. **The diff report writes nothing to the status log** (p12a U1.13, U1.14): all its result lines go to the diff panel. HLR-176c's threshold ("the status log's last line is the outcome", 14 arms) therefore needs a new log line for this action (Q-3).
3. **The A2L load's last log line is not its `set_progress` message.** `Loaded <name>` (the message) is followed by `A2L loaded: <name>`, and `test_b100_focus.py` reads `A2L loaded:` from the last log row 8 times. E1's glossary ("outcome = the message of the last `set_progress` call") and HLR-176c's threshold cannot both hold for this action (Q-3).
4. **LLR-172.6b's rationale (backlog B5) says that "after 9b (B-2), an A2L pick loads in place with no copy".** 9b reversed that (A9b-05): the A2L pick goes through `load_a2l_from_path`, including `copy_into_workarea` with its 256 MiB cap and link re-check. The new pick-time check therefore matters mainly for the data arm (`load_selected_file`), which has no check today (U2.2–U2.5).
5. **The pick re-check cannot live in 9b's verdict.** `_load_dialog_verdict` must make 0 filesystem calls for a `workarea` choice (9b B55). The refusal is therefore a status line after the dialog closed (S-i), not a `#load_reason` token. LLR-172.6b says "paint the tokens", which a status line satisfies.
6. **LLR-172.5i's absolute arms already pass** (U2.6). Only the relative text raises.
7. **The `project_load` final line is a `Text`, not a `str`** (`set_file_status(safe_text(…))`, `:11942`). S-d makes the final line `safe_text(…).plain`.
8. **E1's "29 files" constraint holds unchanged.** No 9b, 10 or 11 design rebaselines any of the 29 cells (9b deferred its label change to 12a, Q8; Inc 10's and Inc 11's modals are not in the density snapshots).
