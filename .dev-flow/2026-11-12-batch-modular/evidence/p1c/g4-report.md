Work tree intact (only the 8 assigned test files modified). Report follows.

---

# REPORT — Group 4 (hazards.md rows 73–83), source-reading tests → package layout

## 1. Files changed, one line per row

| Row | File | What changed |
|---|---|---|
| 73 | `tests/test_b97_key_bar.py` | PATH-KEY: `APP_PY/SDB_PY/SJ_PY` path keys re-pointed to the real defining modules — class attributes stay `core.py`/`S19TuiApp` (`_FIND_GOTO_INPUTS`, `_SCREEN_LEGEND_SECTIONS`), actions to `NavigationMixin` (navigation.py) / `A2lViewMixin.action_a2l_describe_tag` (a2l_view.py), `AbDiffPanel.BINDINGS`→`screens_directionb/ab_diff.py`, `SplitJoinWindow.BINDINGS`→`segment_split_view.py`; BINDINGS import now uses the full dotted module (`Path(rel).with_suffix()`), not `s19_app.tui.<stem>`. Verified each target holds its symbol (grep). |
| 74 | `tests/test_import_census.py` | COUNT/PATH-KEY: `MEASURED_SAFE_TEXT_CONSUMERS` re-pointed to real submodule names (`s19_app.tui.app.<m>`, `s19_app.tui.screens_directionb.<m>` + both package `__init__`s); sdb text read via `ps.package_text("screens_directionb")`; expectation `from ..utils import safe_text` → `from ...utils import safe_text`. Also dropped the stale `s19_app.tui.a2l_parameter_picker` entry (see §4 deviation 1). |
| 75 | `tests/test_render_hexview.py` | COUNT/PATH-KEY: `MEASURED_CONSUMERS` re-pointed (`s19_app.tui.app.deps/file_load/hex_view`, `s19_app.tui.screens_directionb.ab_diff` in place of the two single-file names). |
| 76 | `tests/test_render_hexview.py` | READ-PACKAGE: app `app.py` single-file AST walk → `ps.package_modules("app")`, owner package for import resolution `s19_app.tui` → `s19_app.tui.app`. |
| 77 | `tests/test_tui_commandbar.py` | MERGED-CLASS: `_B79_APP_SOURCE` path read dropped; `S19TuiApp` method census now computed from `ps.merged_class()`; extracted the shared `_class_members` helper (used by row 78 too). |
| 78 | `tests/test_tui_commandbar.py` | PATH-KEY + MERGED-CLASS: anchor corpus changed from a fixed old-file list to every file of both packages (`_b79_anchor_corpus()` via `ps.package_modules("app"/"screens_directionb")`) + the 3 test files; `S19TuiApp` member table from `_class_members(ps.merged_class())`. |
| 79 | `tests/test_tui_hexview.py` | READ-PACKAGE: `app.py` single-file AST → `ps.package_modules("app")` walk; message/ docstring updated. |
| 80 | `tests/test_tui_variants.py` | READ-PACKAGE: `app.py` source parse → `ps.package_tree("app")`. |
| 81 | `tests/test_filename_markup_safety.py` | READ-PACKAGE: `app.py` source read → `ps.package_tree("app")`; removed `import s19_app.tui.app as app_module`, added `ps` import; docstring updated. |
| 82 | `tests/test_tui_report_attribution.py` | GETSOURCE: `inspect.getsource(app_module)` → `inspect.getsource(S19TuiApp._start_generate_report_worker)` (dedented); `_generation_inside_valueerror_span` extended to also match the module-aliased `deps.generate_project_report(...)` (Attribute), see §4 deviation 3. |
| 83 | `tests/test_tui_report_attribution.py` | GETSOURCE: `inspect.getsource(app_module)` + text slicing → `inspect.getsource(S19TuiApp._start_generate_report_worker)`. |

**Rows not finished: none.** All 11 rows (73–83) adapted. All 11 adapted nodes verified `11 passed` on the unmutated adapted tree.

## 2. Negative controls (each adapted test goes RED under its one-line product mutation)

Command pattern (run_nc.sh): `cp -a _base nc-<row>`; `python3 mutate.py <row>`; then
`env -i PATH=/usr/bin:/bin HOME=<state>/zq_iso_user TMPDIR=<state>/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 /data/miniconda3/envs/s19ci/bin/python -m pytest -q -p no:cacheprovider <node> < /dev/null`.

| Row | Mutation | RED assertion line |
|---|---|---|
| 73 | a2l_view.py: `'if self._active_screen_key != "a2l" or not self.current_a2l_data:'` → `'if not self.current_a2l_data:'` | `AssertionError: a2l d: 'if self._active_screen_key != "a2l" or not self.current_a2l_data:' is no longer inside s19_app/tui/app/a2l_view.py::A2lViewMixin.action_a2l_describe_tag` |
| 74 | ab_diff.py: append `def safe_text(value: str)` | `AssertionError: safe_text must be defined only at s19_app.utils, found: {'s19_app.tui.screens_directionb.ab_diff': [1212], 's19_app.utils': [44]}` |
| 75 | app/flow.py: append `from ...render.hexview import render_hex_view_text` | `AssertionError: hexview importer set drifted from the measured set: extra=['s19_app.tui.app.flow'] missing=[]` |
| 76 | remove `from ...range_index import` from `__init__.py`, `file_load.py`, `hex_view.py`, `mac_view.py` | `AssertionError: app.py must import the range primitives from the engine` (`assert 's19_app.range_index' in {...}`) |
| 77 | a2l_view.py: append `def on_command_bar_find(self)` | `AssertionError: HLR-121 requires a class-qualified census of 0 for all seven symbols; these are still defined: ['S19TuiApp.on_command_bar_find']` |
| 78 | navigation.py: append comment citing `S19TuiApp.no_such_member` | `AssertionError: these cited symbol anchors do not resolve: ['S19TuiApp.no_such_member']. …` |
| 79 | shell.py: append method body `from s19_app.tui.hexview import _x` | `AssertionError: app package imports private hexview helpers: ['_x'] -- LLR-003.2 violation` (re-run this session) |
| 80 | shell.py: append `_nc_new_parse_caller` calling `self._parse_loaded_file()` | `AssertionError: unexpected _parse_loaded_file call sites: ['_nc_new_parse_caller', '_start_load_worker', 'load_selected_file'] …` |
| 81 | patch.py: remove one `markup=False,` | `AssertionError: these self.notify() calls embed dynamic (file-derived) text but do not pass markup=False (markup injection sink): ['line 1116']` |
| 82 | reports.py: `except Exception as exc` → `except ValueError as exc` | `AssertionError: _start_generate_report_worker: generate_project_report is called at line(s) [147] inside a try that catches ValueError …` |
| 83 | reports.py: duplicate `f"Report failed: …"` build | `AssertionError: the tool-failure status is built 2 times; it must be built once, in the shared helper` |

All 11 negative controls RED. (Note: row 79's original logged run hit an `ImportError` at collection from an earlier module-level mutation; I re-applied the corrected method-body mutation and captured the RED assertion above.)

### [V] old-version (unadapted) results
- **Row 79 [V] — old version stayed GREEN (vacuity confirmed):** `1 passed in 0.08s`. The old test read only `s19_app/tui/app/__init__.py` (via `app.__file__`), so the private import injected in `shell.py` was never seen.
- **Row 77 [V] — old version did NOT stay green:** it hard-fails with `FileNotFoundError: [Errno 2] No such file or directory: 's19_app/tui/app.py'` (the `[V]` annotation in the table implies vacuous-green, but the path is hard-deleted, so it is hard-broken — see §4 deviation 2).

## 3. Partial acceptance logs — failures

The three `../scratch/*.log` acceptance artifacts are truncated **progress-bar-only** output (`bringing up nodes...` + `....F....` lines), with **no node ids and no FAILED/summary lines**, so the `F` markers cannot be attributed to specific nodes:
- `acceptance.log` (268 B, `-n 4`): 4 `F` markers, cut off mid-run at ~65%.
- `acceptance_serial.log` / `acc_deselect.log`: one `F` marker each, truncated.

What I **could** verify deterministically:
- All **11 adapted nodes pass** on the unmutated adapted tree (`11 passed in 14.88s`).
- **Pre-existing base failure found and fixed by my adaptation:** `test_import_census.py::test_tc653_safe_text_import_census` fails at base `4f721985` (`missing=['s19_app.tui.a2l_parameter_picker']`) because the old measured set carried a stale entry; my adaptation drops that entry (see §4 deviation 1), and the adapted node passes.
- I could **not** run the full 8-file suite to completion on this loaded runner (serial + `-n 4` both timed out at 600 s), so the remaining `F` markers in `acceptance.log` are un-attributed / not shown pre-existing. The orchestrator's other-runner acceptance will settle them.

## 4. Deviations (with evidence)

1. **Row 74 — dropped a stale measured entry the table didn't mention.** `git show 4f721985:s19_app/tui/a2l_parameter_picker.py | grep -n 'safe_text\|utils\|scrub'` → empty (it never imported `safe_text`). The old `MEASURED_SAFE_TEXT_CONSUMERS` listed `s19_app.tui.a2l_parameter_picker`, so the old test failed at base (`AssertionError: … missing=['s19_app.tui.a2l_parameter_picker']`). My adaptation removes that stale name (comment documents it) so the census is set-equality-correct on the new layout.
2. **Row 77 `[V]` annotation is inaccurate.** The table marks row 77 `MERGED-CLASS [V]` (silently green if left alone), but the unadapted test hard-fails with `FileNotFoundError` on `s19_app/tui/app.py` (the path is gone, not a thin shim). The `MERGED-CLASS` adaptation is still correct; only the vacuity label is wrong.
3. **Row 82 — census had to become alias-aware (faithful extension beyond "GETSOURCE").** The table's adaptation is "GETSOURCE on `S19TuiApp._start_generate_report_worker`", but after the split the `generate_project_report` call moved behind the `deps` module alias (`deps.generate_project_report(...)`). I extended `_generation_inside_valueerror_span` to match the direct `ast.Name` **and** the module-aliased `ast.Attribute`; otherwise the span census would be silently vacuous post-split (a defect the negative control confirmed RED).

## 5. Open questions

1. The 4 unattributed `F` markers in `acceptance.log` — which nodes? They are neither my 11 adapted nodes (all pass) nor `test_tc653` (now fixed). No node names exist in the truncated logs; the orchestrator's clean runner must confirm whether they are pre-existing/flaky on the loaded runner.
2. Group 4 header says "13 rows" but the table enumerates 11 (73–83). I treated the task's explicit "rows 73–83" as authoritative; if two more rows belong to group 4 they were not in the table I was given.
3. Full local acceptance could not be completed (600 s timeout on this loaded runner, both serial and `-n 4`) — consistent with why the two prior sessions ran out of time.

`git diff` is unchanged (8 test files only); `../scratch` deleted; `../state` (the acceptance env dir referenced by the task) left intact.
PI_EXIT=0
