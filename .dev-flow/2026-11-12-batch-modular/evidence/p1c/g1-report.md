# REPORT — batch-modular P1c group 1 (rows 1–18) — REPORT-ONLY continuation

Verified against the frozen work tree (`HEAD b606ff6c`, branch `work`). No file in the work tree was edited. Negative controls were re-run from the pre-existing `../scratch/nc-<row>` copies (mutation already applied there); all `nc-*` dirs and my `nc-results` were deleted afterwards.

## 1. Files changed (per hazards.md row)

| Row | File / node | What changed |
|---|---|---|
| 1 | test_b100_a2l_progress.py::test_tc_b100_73_one_argument_callers_outside_the_app_are_unchanged | PATH-KEY: exclude by `package_source.tui_dir()/"app"` (assert `is_dir`), skip `source.is_relative_to(app_dir)` instead of `source.name == "app.py"` |
| 2 | test_b100_busy.py::test_tc_b100_50_begin_busy_is_called_only_from_the_one_label_helper | MERGED-CLASS: `_class_methods`→`_merged_methods` (from `merged_class`); removed module-level `APP_SOURCE` |
| 3 | test_b100_busy.py::test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event | MERGED-CLASS (same `_merged_methods` swap) — **PRE-EXISTING FAILURE (see §3)** |
| 4 | test_b100_busy.py::test_tc_b100_51_only_the_seam_sets_the_bar | MERGED-CLASS `[V]` (same swap) |
| 5 | test_b100_busy.py::test_tc_b100_51_workers_take_the_run_generation | READ-PACKAGE: `package_tree("app")` for the `gen=` call census |
| 6 | test_b100_busy.py::test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers | MERGED-CLASS (same swap) — **PRE-EXISTING FAILURE (see §3)** |
| 7 | test_b100_busy.py::test_tc_b100_51_every_save_abort_return_ends_its_run_first | MERGED-CLASS (same swap) |
| 8 | test_b100_busy.py::test_tc_b100_51_file_load_reads_the_copy_size_before_the_worker | MERGED-CLASS via `_merged_methods()["load_from_path"]` |
| 9 | test_b100_load_dialog.py::test_tc_b100_40_one_router_receives_every_dialog_result | READ-PACKAGE: `_load_dialog_push_sites(package_tree("app"))` (signature now takes a parsed Module) |
| 10 | test_b100_reuse.py::test_tc_b100_57_export_holds_no_byte_identity_rule | PATH-KEY: rule key `("s19_app/tui/app.py","_abort_save")` → `("s19_app/tui/app/save_commit.py","_abort_save")` |
| 11 | test_b100_reuse.py::test_tc_b100_01_app_placements_name_the_workarea_root | READ-PACKAGE (`package_tree("app")`); added local `_callee_name` so the census also matches module-qualified `deps.<placement>(...)` calls (split moved some placements into `deps`) |
| 12 | test_b100_save_guards.py::test_tc_b100_07_ast_census_every_post_creation_return_removes | READ-PACKAGE: `_app_module_ast()` now returns `package_tree("app")` |
| 13 | test_b100_session_reset.py::test_tc_b100_09_domain_matches_the_live_source_census | MERGED-CLASS `[V]`: `_source_census` uses `merged_class("S19TuiApp")` — **PRE-EXISTING FAILURE (see §3)** |
| 14 | test_b100_session_reset.py::test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag | MERGED-CLASS (same `_source_census`) — **PRE-EXISTING FAILURE (see §3)** |
| 15 | test_b100_session_reset.py::test_tc_b100_08_call_site_census | PATH-KEY: expected caller list `["tui/app.py"]` → `["tui/app/project_load.py"]` |
| 16 | test_b100_session_reset.py::test_tc_b100_08_the_one_reset_call_sits_in_the_install_handler | NONE — unchanged; PASS |
| 17 | test_b100_workers.py::test_tc_b100_53_workers_read_only_their_frozen_request | MERGED-CLASS `[V]` (`_merged_methods`) + READ-PACKAGE (`package_tree("app")` for `parse_a2l_cached`, now in `deps.py`) |
| 18 | test_b100_workers.py::test_tc_b100_53_session_is_written_only_on_the_main_thread | MERGED-CLASS `[V]`: `source_census()` uses `merged_class("S19TuiApp")`; CSS-path part untouched (`"../styles.tcss"` works) |

Rows **not finished**: none of the 17 adapted rows remain broken — 13 adapted rows PASS, 4 fail only because they fail identically at base (pre-existing, see §3). Row 16 (NONE) passes. Helper `tests/support/package_source.py` was used, not modified.

## 2. Negative controls (all RED) + [V] old-version results

Command template (one node, isolated env, `< /dev/null`, timeout 300, in the pre-existing `../scratch/nc-<row>` copy):
`cd ../scratch/nc-<row> && env -i PATH=/usr/bin:/bin HOME=$S/zq_iso_user TMPDIR=$S/tmp PYTHONDONTWRITEBYTECODE=1 LANG=C.UTF-8 /data/miniconda3/envs/s19ci/bin/python -m pytest -q -p no:cacheprovider tests/<file>::<node> < /dev/null`

| Row | Mutation (product file) | RED assertion line (pasted) |
|---|---|---|
| 1 | 2-arg call `parse_a2l_file(a2l_path, None)` in `services/flow_execution_service.py` | `E AssertionError: ['s19_app/tui/services/flow_execution_service.py:381']` (`assert bad == [], bad`) |
| 2 | `self.begin_busy("report","R",("a",))` in `app/navigation.py` | `E AssertionError: ['_is_layout_visible', '_busy_begin_action']` (`assert sites == ["_busy_begin_action"]`) |
| 3 | delete `step_busy` (`call_from_thread(self.step_busy,"report",gen,2)`) in `app/reports.py` | `E AssertionError: [('_start_generate_report_worker','step','report',2,'0/1'), ('load_a2l_from_path','begin','a2l_load',None,'0/1'), ('_install_attached_a2l','end','a2l_load',None,'0/1'), ('_start_load_worker','end','file_load',None,'0/1')]` (`assert missing == []`) |
| 4 | `self.query_one("#progress_bar")` in `app/navigation.py` | `E AssertionError: [('_is_layout_visible', 23)]` (`assert queries == []`) |
| 5 | `self._start_load_worker(copied)` without `gen=` in `app/file_load.py` | `E assert [533] == []` (`assert [c.lineno for c in calls if not any(k.arg=="gen" ...)] == []`) |
| 6 | remove `end_busy` from `_on_a2l_attach_failed` in `app/file_load.py` | `E AssertionError: [('load_a2l_from_path','begin','a2l_load',None), ('_install_attached_a2l','end','a2l_load',None), ('_on_a2l_attach_failed','end','a2l_load',None)]` (`assert missing == []`) |
| 7 | abort arm returns plain string `return "plain string"` in `app/save_commit.py` | `E AssertionError: [706]` (`assert not_outcome == []`) |
| 8 | swap `copied.stat()` after `_start_load_worker` in `app/file_load.py` | `E AssertionError: ([533], [532])` (`assert stats[0] < starts[0]`) |
| 9 | own callback `self._confirm_then_load` in `app/project_load.py` | `E AssertionError: [('action_load_file','self._handle_load_dialog'), ('action_load_project','self._confirm_then_load')]` (`assert sorted(sites) == [...])` |
| 10 | `a.read_bytes()==b.read_bytes()` helper in `app/navigation.py` | `E AssertionError: byte-identity census drifted: unexpected {('s19_app/tui/app/navigation.py','_fake_byte_identity')}, declared-but-missing set()` |
| 11 | drop `workarea_root=` once in `app/file_load.py` | `E AssertionError: app-package call copy_into_workarea at line 491 must pass workarea_root explicitly` |
| 12 | `raise RuntimeError("nc")` after mkdir in `app/save_commit.py` | `E AssertionError: raise after the folder's creation: lines [671]` (`assert raises == []`) |
| 13 | `self._brand_new = 1` in a mixin (`app/navigation.py`) | `E AssertionError: unclassified census names: ['_brand_new', '_right_gesture']` |
| 14 | `self._pending_request = r` in a mixin (`app/navigation.py`) | `E AssertionError: ['_pending_request', '_quit_pending', '_right_gesture']` (`assert census - base == {"_quit_pending"}`) |
| 15 | second caller `self._reset_project_session()` in `app/a2l_view.py` | `E AssertionError: ['tui/app/a2l_view.py', 'tui/app/project_load.py']` (`assert callers == ["tui/app/project_load.py"]`) |
| 17 | `_ = self.current_file` read in `_parse_data_file` (`app/projects.py`) | `E AssertionError: session reads reachable from a worker: {'_project_load_worker -> _parse_data_file': ['current_file']}` (`assert hits == {}`) |
| 18 | `self._variant_set = None` in Save worker (`app/save_commit.py`) | `E AssertionError: session written off the main thread: ['_variant_set', '_variant_set_value']` (`assert off_main == []`) |

**Caveat on rows 3, 6, 13, 14:** those four tests are *already* RED without the mutation (pre-existing, §3). Their negative controls still add the expected mutated item to the failure list, so the adapted tests do detect their mutations — but the "GREEN→RED" step was not clean for those four.

**[V] old-version result** (old file from `git show HEAD:<file>` dropped into the mutated `nc-<row>` copy, same command): the old version did **NOT** stay GREEN on the split layout — all five fail loudly because `Path(app_module.__file__)` now resolves to the package `__init__.py`, which has no `class S19TuiApp`:

| Row | Old-version result |
|---|---|
| 2 | `AssertionError: class S19TuiApp not found in …/s19_app/tui/app/__init__.py` (RED, not green) |
| 4 | same `class S19TuiApp not found … __init__.py` (RED, not green) |
| 13 | `StopIteration` in `_source_census` (ERROR, not green) |
| 17 | `AssertionError: worker functions not found in app.py: ['_project_load_worker','_save_project_worker','_a2l_attach_worker']` (RED, not green) |
| 18 | `AssertionError: []` (`cache_writes` empty, runtime) (RED, not green) |

So the `[V]` "silently GREEN" prediction did **not** materialise for any of these five rows: the unadapted tests fail loudly rather than passing vacuously (they read the now-empty-class `__init__.py`). The adaptation was still required and is correct.

## 3. Failures (adapted tree) — all PRE-EXISTING at base

No partial acceptance logs existed (`pi*.log` only contain `PI_EXIT=124` from the two timed-out sessions). I re-ran the 18 row nodes in the work tree: **14 passed, 4 failed**. The same 4 nodes fail **identically** in `../scratch/base` (= `git archive 4f721985`):

| Node | Base failure == adapted failure |
|---|---|
| test_tc_b100_51_every_baseline_bar_site_maps_to_a_seam_event (row 3) | `[('load_a2l_from_path','begin','a2l_load',None,'0/1'), ('_install_attached_a2l','end','a2l_load',None,'0/1'), ('_start_load_worker','end','file_load',None,'0/1')]` — identical (line 1639 base vs 1637 adapted) |
| test_tc_b100_51_twelve_b_seam_sites_sit_in_the_workers_and_handlers (row 6) | `[('load_a2l_from_path','begin','a2l_load',None), ('_install_attached_a2l','end','a2l_load',None)]` — identical |
| test_tc_b100_09_domain_matches_the_live_source_census (row 13) | `unclassified census names: ['_right_gesture']` — identical |
| test_tc_b100_09_twelve_b_adds_exactly_the_quit_flag (row 14) | `census - base = ['_quit_pending', '_right_gesture']` (extra `_right_gesture`) — identical |

Root causes (all present at base `4f721985`, unrelated to the split): (a) `CENSUS`/`TWELVE_B_SITES` name the `a2l_load` begin in `load_a2l_from_path` but it lives in `_start_a2l_load` (`_busy_begin_action("a2l_load",…)`), and the success end lives in `_install_attached_a2l` emitted via `call_after_refresh(self.end_busy,…)` which `_seam_events` does not unwrap (it only unwraps `call_from_thread`); (b) `_right_gesture` is a real `self._right_gesture` attribute (`app.py:3168` at base, `app/core.py:309` now) that the session-snapshot exclusion list never classified.

## 4. Deviations / findings and open questions

**Findings (not deviations in my adaptation):**
1. `[V]` rows 2/4/13/17/18 are not vacuous as predicted — the old tests error on `__init__.py` instead of staying green. (Adaptation still needed; no product change.)
2. Rows 3, 6, 13, 14 are pre-existing failures at base (identical), so they are acceptable under the acceptance rule; their negative controls are "RED→more-RED" rather than clean "GREEN→RED".
3. Row 11: to keep the same census property I added a small local `_callee_name` matcher (handles `deps.<placement>` module-qualified calls introduced by the split); this is a faithful widening, not a behaviour change.

**Open questions:**
- Should the 4 pre-existing failures (rows 3/6/13/14) be excluded by the orchestrator's acceptance, or are they expected to be fixed in a separate (non-group-1) pass? They are independent of the split.
- I could not complete a full 7-file run of my group in this window (it exceeded 20 min on this runner); the orchestrator's `-n 4` acceptance is the authoritative gate. My verification was limited to the 18 row nodes + helper/hygiene-relevant checks (helper floor intact, no dangling `APP_SOURCE`/`_class_methods` references, all new helpers are called only by the row tests).

Cleanup: `../scratch/nc-*` and `nc-results` deleted; `base`/`state` left in place (not created by me).
PI_EXIT=0
base
state
