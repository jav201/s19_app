# Increment 007 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 7 — Issues Report dedicated screen + dismantle `#workspace_carryover`
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-011.1 (Issues screen layout — dedicated rail screen), LLR-011.2 (Issues behavior preserved), LLR-002.3 (empty-state panel for the re-laid-out Workspace + Issues screens — flagged pending in increment 5). LLR-011.3 (project/A2L labels in the command bar — relocated in increment 4) confirmed not regressed. · **TCs covered:** TC-023, TC-024, TC-037 (Workspace + Issues sub-cases).

---

## 1. What changed

The temporary `.hidden` `#workspace_carryover` container created in increment 5 was **fully dismantled**. It held three things that increment 7 re-homed to their Direction B destinations:

1. **The validation Issues subtree** — the `#validation_issues_filters` row (All/Errors/Warnings buttons), the `#validation_issues_list` `DataTable` and the `#validation_issues_summary` label — was promoted into the real `#screen_issues` rail screen (rail item 5). `#screen_issues` was previously a neutral `ScreenScaffold`; it is now built by a new `_compose_screen_issues` method that yields a `db-screen-title`, an `#issues_content` container holding the lifted Issues subtree, and an `EmptyStatePanel` (LLR-011.1).
2. **The status / log / progress widgets** — `#status_text`, `#progress_bar` and `#log_line_1..4` — were re-homed to a new persistent `#workspace_status_bar` `Container` composed in `compose` directly above the `Footer`. This is the Direction B status-bar home; it is visible on every rail screen so `set_status` / `set_file_status` / `set_progress` and the `_render_log_lines` log tail keep a stable render target whichever screen is active.
3. **The leftover `#project_text` / `#a2l_text` labels** — these were duplicate Status-tile copies of the project/A2L context; the canonical home is the command bar (`CommandBar.set_context_labels`, relocated in increment 4 — LLR-011.3). They were dropped and `update_project_labels` was simplified to write the command bar only. The command-bar copy is the surviving, on-every-screen home — `R-TUI-016` is not regressed.

`#screen_workspace` (recomposed in increment 5) had its `#workspace_carryover` child removed; an `EmptyStatePanel` was added alongside `#workspace_panes` so the no-file Workspace shows the LLR-002.3 neutral prompt instead of three empty panes — increment 5 had explicitly flagged the Workspace empty-state as pending.

The **empty-state wiring (LLR-002.3)** is a new `_apply_empty_state` helper plus a `_EMPTY_STATE_SCREENS` table listing the two content-bearing screens that own both real content and an `EmptyStatePanel` (`screen_workspace` → `workspace_panes`, `screen_issues` → `issues_content`). When `current_file` is `None` the helper hides the real content and shows the panel; once a file is present it does the reverse. It is invoked from `on_mount` (startup state), `action_show_screen` (every rail navigation), and `_apply_prepared_load` (immediately after `current_file` is set by the load pipeline). The helper tolerates an unmounted widget tree (try/except per screen) — the same defensive pattern the existing `_focus_activity_rail` uses — so the headless `_apply_prepared_load` unit tests in `test_tui_app.py` that monkeypatch the renderers are unaffected.

**No renderer / paging / filter logic was modified.** `update_validation_issues_view`, `_populate_issues_datatable`, `precompute_issue_datatable_payload`, `action_validation_issues_page_next/prev`, the `issues_filter_all/error/warning` button branch of `on_button_pressed`, the `validation_issues_list` branch of `on_data_table_row_selected` and `_jump_to_validation_issue_by_index` are byte-identical — every widget id they query (`#validation_issues_list`, `#validation_issues_summary`, `#issues_filter_*`) is preserved, only the parent container changed. `_setup_datatable_columns` still finds `#validation_issues_list` and installs its 7 columns at mount. The Issues `DataTable` height changed from a fixed `height: 12` (tile-sized) to `height: 1fr` (fills the dedicated screen) — a CSS layout change only.

No engine, service, `validation/`, `color_policy.py`, parser, hex-cap constant or new runtime dependency was touched. Composition + CSS only, as in increments 5-6.

## 2. Files modified

**Code / test (3 — under the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/app.py` | modified | Added `_compose_screen_issues` (the dedicated Issues rail screen holding the lifted `#validation_issues_filters` / `#validation_issues_list` / `#validation_issues_summary` subtree + an `EmptyStatePanel`); replaced `ScreenScaffold("screen_issues", ...)` in `compose` with it; added the persistent `#workspace_status_bar` (status text + progress bar + log tail) above the `Footer`. Recomposed `_compose_screen_workspace` to drop `#workspace_carryover` and add an `EmptyStatePanel`. Added `_apply_empty_state` + the `_EMPTY_STATE_SCREENS` table (LLR-002.3); wired it into `on_mount`, `action_show_screen` and `_apply_prepared_load`. Simplified `update_project_labels` to write only the command bar (the old `#project_text`/`#a2l_text` Status-tile copies are gone). Imported `EmptyStatePanel`. Docstrings updated to the PROJECT_RULES.md contract. |
| `s19_app/tui/styles.tcss` | modified | Removed the obsolete `#workspace_carryover.hidden` rule and its carry-over comment. Added the `#workspace_status_bar` rules (border-top divider, panel background, auto height) and the Issues Report dedicated-screen rules (`#issues_content`, `#issues_content.hidden`); changed `#validation_issues_list` from `height: 12` to `height: 1fr` so the table fills its dedicated screen. |
| `tests/test_tui_directionb.py` | modified | Added the increment-7 block (11 tests): TC-023 ×3 (Issues table is the primary content of `#screen_issues`; `#workspace_carryover` fully removed + status/progress/log widgets not orphaned; status widgets reachable on every screen), TC-024 ×5 (severity filters narrow; the filter *button* handler routes; paging advances/clamps; severity coloring round-trips through `precompute_issue_datatable_payload` with distinct per-severity styles; row-select jump-to-source), TC-037 ×3 (Workspace + Issues empty-state with no file; empty-state clears when a file loads). Updated 4 pre-existing cases in the same file for the new LLR-002.3 behavior: the three TC-017 Workspace-layout tests now install a `LoadedFile` (via the new `_install_prg_loaded_file` helper) so the panes are visible before their width-regime assertions; `test_tc037_scaffold_screens_carry_empty_state` now expects 6 panels (4 scaffolds + Workspace + Issues) since Issues is no longer a scaffold. Module docstring extended to increments 2-7. |

**Documentation:**
- `.dev-flow/2026-05-20-batch-02/03-increments/increment-007.md` — this review packet.

**File count:** 3 — under the ≤5 cap.

## 3. How to test

```bash
# 1. Static check (ruff is NOT installed in this environment — py_compile substituted)
python -m py_compile s19_app/tui/app.py tests/test_tui_directionb.py

# 2. Import smoke
python -c "import s19_app.tui"

# 3. The new increment-7 tests only
python -m pytest -q tests/test_tui_directionb.py -k "tc023 or tc024 or (tc037 and (workspace or issues))"

# 4. Full directionb + commandbar suites + the two app-pipeline tests touched by _apply_empty_state
python -m pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py

# 5. Full suite — must not regress from the 327/2/3/0 baseline
python -m pytest -q
```

An additional `App.run_test()` smoke (run ad-hoc, see §4) loads the public `examples/case_04_bad_checksums/firmware.s19` fixture, asserts `#workspace_carryover` is gone, drives the Issues rail screen end-to-end (render, severity-filter button, paging, jump-to-source) and verifies the empty-state flips on file load.

## 4. Test results

**`python -m py_compile s19_app/tui/app.py tests/test_tui_directionb.py`** — actual output:
```
PY_COMPILE OK
```
Note: `ruff` is **not installed** in this environment (`ModuleNotFoundError: No module named 'ruff'`). Per the increment instructions `python -m py_compile` was substituted as the static check and passes on both changed Python files. `styles.tcss` is parsed by the Textual engine on every `run_test()`-based case (50 directionb + 16 commandbar cases + the full suite exercise it); a malformed rule would surface as a `StylesheetError` at mount. Recommend `ruff check .` in CI / a ruff-equipped environment before merge.

**`python -c "import s19_app.tui"`** — actual output:
```
IMPORT OK
```

**New increment-7 tests** — `python -m pytest -q tests/test_tui_directionb.py -k "tc023 or tc024 or (tc037 and (workspace or issues))"` — actual output:
```
...........                                                              [100%]
11 passed, 39 deselected in 5.76s
```
11 new increment-7 cases: TC-023 ×3, TC-024 ×5, TC-037 ×3 (Workspace + Issues empty-state).

**Directionb suite** — `python -m pytest -q tests/test_tui_directionb.py` — actual output:
```
..................................................                       [100%]
50 passed in 34.74s
```
39 prior (increments 2-6) + 11 new increment-7 = 50. The 3 TC-017 and 1 TC-037 pre-existing cases updated for the LLR-002.3 empty state still pass with their layout/empty-state intent intact.

**Directionb + commandbar + the two `_apply_empty_state`-touched app tests** — `python -m pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py tests/test_tui_app.py::test_load_selected_file_attaches_mac_to_loaded_binary tests/test_tui_app.py::test_apply_prepared_load_chains_updates_via_call_later tests/test_tui_app.py::test_update_validation_issues_view_empty_state` — actual output:
```
..................................................................       [100%]
66 passed in 42.18s
```
The two `test_tui_app.py` pipeline tests that monkeypatch the renderers and call `_apply_prepared_load` on an unmounted app pass — `_apply_empty_state` no-ops when the widget tree is absent (the `_focus_activity_rail` defensive pattern).

**Full suite** — `python -m pytest -q` — actual output (tail):
```
338 passed, 2 skipped, 3 xfailed in 115.94s (0:01:55)
```
Baseline was **327 passed / 2 skipped / 3 xfailed / 0 failed**. The 11 new increment-7 tests bring the total to **338 passed** (327 + 11); the 2 skipped + 3 xfailed are unchanged (pre-existing). 0 failed — **no regression**. No test was silently skipped.

> Note on the first full-suite run during dev: 6 tests failed (4 in `test_tui_directionb.py` — the TC-017/TC-037 cases that assumed the no-file Workspace showed panes, now correctly hidden by the new empty state; 2 in `test_tui_app.py` — `_apply_empty_state` querying an unmounted tree). All 6 were genuine consequences of the LLR-002.3 wiring and were resolved within the 3-file scope: the 4 directionb cases updated to install a file before measuring layout (intent preserved — only the precondition changed), and `_apply_empty_state` made defensive. The final run is clean.

**`App.run_test()` Issues-screen end-to-end smoke** (public `case_04_bad_checksums/firmware.s19`) — actual output:
```
all rows (page-capped): 60 page_size: 200
error-filter rows: 20
paging: 0 -> 0
cell styles produced: 0
jump-to-source OK, row keys: 20
SMOKE OK
```
With the public bad-checksums S19 fixture loaded and 60 synthetic validation issues injected: `#workspace_carryover` is absent; the Issues rail screen renders all 60 issues (page size 200 — one page); the `#issues_filter_error` button press narrows the table 60→20; jump-to-source resolves a row key without error. `paging: 0 -> 0` is correct — 60 issues at page size 200 is a single page so page-next stays at window 0 (the TC-024 paging test uses `page*2+5` = 405 issues to exercise a real multi-page advance). `cell styles produced: 0` is also correct — the worker-precompute cache (`_validation_issue_cell_styles`) is only populated by the threaded load path; the unit-injection path renders via `precompute_issue_datatable_payload` on the fly, which TC-024's severity test asserts on directly. The smoke temp state was not persisted.

## 5. Risks

- **`EmptyStatePanel` id duplication.** There are now 6 `EmptyStatePanel` widgets in the tree (4 `ScreenScaffold` slots + Workspace + Issues), all carrying the same id `#empty_state_panel`. This predates increment 7 (5 scaffolds already shared the id). Textual permits duplicate ids for CSS matching, but `query_one("#empty_state_panel")` would be ambiguous — `_apply_empty_state` and every increment-7 test query the panel **by type, scoped to a screen** (`screen.query_one(EmptyStatePanel)` / `screen.query(EmptyStatePanel)`), never by the shared id, so the ambiguity is never hit. If a future increment needs to query a single empty-state panel by id, the ids should be made unique first.
- **`_apply_empty_state` defensive no-op.** The helper swallows any exception per screen when the widget tree is not yet mounted, so the headless `_apply_prepared_load` unit tests keep working. This matches `_focus_activity_rail`'s existing pattern. The trade-off: a genuine missing-widget bug inside a mounted app would also be silently swallowed. Mitigation: the increment-7 `run_test()` tests exercise the mounted path on every screen and would fail loudly if a screen lost its panel or content child.
- **Status bar is always visible, even with no file.** `#workspace_status_bar` shows "Ready." and an empty progress bar / log tail at startup. This is the intended Direction B status-area behavior (LLR-013.2 — the status bar is persistent) and matches the pre-batch Status tile, which also showed "Ready." before any load. The progress bar renders at 0% until a load drives it — unchanged from pre-batch.
- **Issues `DataTable` height regime.** `#validation_issues_list` moved from `height: 12` to `height: 1fr`. On a very short terminal the filter row + summary line + `1fr` table still lay out without clipping at the 80×24 minimum (the table simply gets fewer visible rows). Not snapshot-pinned here — the Issues screen under {compact, comfortable} × {80×24, 120×30, 160×40} is verdicted by the increment-12 snapshot matrix.
- **No visual / interactive verification.** All checks are headless (`App.run_test()` / `pytest`). Real-terminal rendering of the dedicated Issues screen, the relocated status bar above the footer, and the empty-state panels was not eyeballed. A manual TUI pass is advisable before batch close.

## 6. Pending items

- **Manual TUI pass** — launch `s19tui --load examples/case_04_bad_checksums/firmware.s19`, press `5` to open the Issues Report rail screen, confirm the table / filter buttons / summary render and the All/Errors/Warnings filters and paging respond; press `1` with no file to confirm the Workspace empty-state panel; confirm the status bar above the footer shows status text and the progress bar. Deferred to the Phase-4 validation gate.
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **`EmptyStatePanel` id uniqueness** — see §5; consider making the 6 panel ids unique in a later increment if any code needs to query a single panel by id.
- **REQUIREMENTS.md traceability** — the candidate `R-TUI-030` (rail-screen empty state) and the Issues-screen rows, if mapped, should be refreshed to cite `test_tui_directionb.py` TC-023/TC-024/TC-037. Not done here (out of the 3-file scope; flagged for the docs increment).
- **Snapshot baselines (increment 12)** — the dedicated Issues screen and the re-homed status bar under the density × size matrix are verdicted by the increment-12 snapshot matrix.

## 7. Suggested next task

**Increment 8 — Modal re-skin (Load / Save / Load-Project)** (LLR-015.1, LLR-015.2). Re-skin the three `screens.py` modals (`LoadFileScreen`, `SaveProjectScreen`, `LoadProjectScreen`) to the Calm Dark tokens — replace hard-coded hex colors in their per-screen `DEFAULT_CSS` with `$accent-calm` / `$bg-*` / `$fg-*` / `$rule` token references; behavior, `validate_project_files`, `SaveProjectPayload`, path resolution and the `.s19tool/` workarea layout stay untouched (LLR-015.2 / C-1 / A-5). This increment is **security-adjacent** (path containment via `resolve_input_path` / `validate_project_files` — S-4) and should be flagged for `security-reviewer` confirmation that path handling is unchanged; TC-034 re-runs the existing containment tests, TC-033 is an inspection checklist.

**Do not start increment 8 — this increment (7) is complete and stops here.**
