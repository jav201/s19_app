# Increment 005 — Review Packet

**Batch:** batch-02-direction-b-restyle (Direction B "Rail + Command" view-layer restyle)
**Increment:** 5 — Workspace screen 3-pane re-layout
**Phase:** 3 — Implementation
**Date:** 2026-05-20
**Branch:** `dev-flow/batch-02-direction-b-restyle`
**LLRs covered:** LLR-008.1 (Workspace three-pane structure + two-regime width layout), LLR-008.2 (Workspace data wiring unchanged) · **TCs covered:** TC-017, TC-018.

---

## 1. What changed

`#screen_workspace` was re-composed from the pre-batch 5-tile `#main_layout` grid (Workarea Files, Data Sections, Hex Viewer, A2L summary, Status) into the Direction B three-pane Workspace defined by LLR-008.1: a `Horizontal` `#workspace_panes` holding a left data ranges/sections pane (`#ws_left`), a center hex pane (`#ws_center`), and a right context pane (`#ws_right`).

The **center hex pane reuses the pre-batch hex subtree verbatim** — `#hex_controls` (with `#search_input` / `#search_button` / `#goto_input` / `#goto_button`) and `#hex_scroll` / `#hex_view` — so `update_hex_view`, `_handle_goto`, `_handle_search` and the increment-4 command-bar adapters (which copy text into `#search_input` / `#goto_input`) keep working unmodified. No `update_*` renderer logic was touched. The left pane hosts `#files_list` (Workarea Files) and `#sections_list` (the `update_sections` render target); the right context pane hosts `#a2l_view` (the `update_a2l_view` render target).

The Issues table and the status/log widgets are no longer Workspace panes per the increment-plan (Issues → its own rail screen in increment 7; project/A2L labels → command bar, already done in increment 4). However the renderers that still write to those widgets — `update_validation_issues_view`, `update_project_labels` (still writes `#project_text` / `#a2l_text`), `set_status` (`#status_text`), the log tail (`#log_line_1..4`), `#progress_bar`, and the `issues_filter_*` button handlers — have **not** been modified this increment (C-1 / scope: pane composition + CSS only). To avoid orphaning any of those renderers, the Issues `DataTable` + filters + summary and the `status_text` / `project_text` / `a2l_text` / `progress_bar` / `log_line_*` widgets were lifted intact into a new `.hidden` container `#workspace_carryover` inside `#screen_workspace`. They stay query-able (renderers keep working) but render nothing (not a fourth pane — LLR-008.1's three-pane structure is preserved). Increment 7 promotes the Issues subtree into `#screen_issues` and dismantles this carry-over.

The two-regime width layout (LLR-008.1 / LLR-007.1) is implemented in `styles.tcss`:
- **`>= 120` columns (fixed regime):** `#ws_left` `width: 22`, `#ws_right` `width: 40`, `#ws_center` `width: 1fr`.
- **`< 120` columns (proportional regime):** under `#workspace_body.width-narrow`, `#ws_left` `width: 24%`, `#ws_right` `width: 30%`, `#ws_center` stays `width: 1fr`; the activity rail collapses to 4 columns.

While wiring the rail collapse a **pre-existing latent CSS defect from increment 3** was found and fixed: the increment-3 collapsed-rail rule was keyed `#workspace_body.width-narrow #rail_slot`, but `#rail_slot` is a *sibling* of `#workspace_body` (both children of `#workspace_shell`), not a descendant — so the descendant selector never matched and the rail stayed 22 columns wide at `< 120` columns. This was latent because no increment-2/3 test exercised the rail width at 80×24; TC-017 (which LLR-008.1 requires to assert the collapsed 4±1 rail) exposed it. The fix: `_apply_width_regime` now toggles `width-narrow` on **both** `#workspace_shell` and `#workspace_body` (the increment-2/3 tests that assert the class on `#workspace_body` keep passing), and the collapsed-rail rule was re-keyed to `#workspace_shell.width-narrow #rail_slot` so it reaches the rail. The per-screen proportional pane rules stay keyed on `#workspace_body`.

No engine, service, `color_policy.py`, parser, `update_*` renderer, `find_string_in_mem`, `_handle_goto`, or hex-cap constant was modified. No new runtime dependency was added.

## 2. Files modified

**Code / test (3 — under the ≤5 cap):**

| File | Status | Purpose |
|------|--------|---------|
| `s19_app/tui/app.py` | modified | Re-composed `_compose_screen_workspace`: the 5-tile `#main_layout` grid → `#workspace_panes` (`Horizontal` of `#ws_left` / `#ws_center` / `#ws_right`) + the hidden `#workspace_carryover` keeping renderer-targeted widgets in the tree. Center pane reuses the pre-batch `#hex_controls` / `#hex_scroll` / `#hex_view` / `#search_input` / `#goto_input` subtree verbatim. `_apply_width_regime` now toggles `width-narrow` on `#workspace_shell` as well as `#workspace_body` so the collapsed-rail rule can reach `#rail_slot`. Docstrings updated to the PROJECT_RULES.md contract. |
| `s19_app/tui/styles.tcss` | modified | Removed the obsolete `#main_layout` grid + `#files_panel` / `#sections_panel` / `#hex_panel` / `#a2l_panel` / `#status_panel` rules; added the Workspace 3-pane rules — `#workspace_panes` horizontal layout, `.db-pane` panel chrome, the `>= 120` fixed-width rules (`#ws_left` 22 / `#ws_right` 40 / `#ws_center` `1fr`) and the `< 120` proportional rules under `width-narrow` (24% / 30% / `1fr`), `#workspace_carryover.hidden`, density padding on `.db-pane`. Re-keyed the collapsed-rail rule from `#workspace_body.width-narrow` to `#workspace_shell.width-narrow`. Dropped the dead `#status_title` selector. |
| `tests/test_tui_directionb.py` | modified | Extended with TC-017 (3 cases — three named panes at the fixed regime 120×30/160×40, left-to-right pane order + renderer-target ownership, proportional regime at 80×24 with collapsed rail) and TC-018 (3 cases — panes populate from a `prg.s19` `LoadedFile` via the unchanged `update_sections` / `update_hex_view`; hex-cap constants unchanged; `update_hex_view` output bounded by `MAX_HEX_ROWS`). Module docstring updated to cover increments 2-5. |

**File count:** 3 — under the ≤5 cap.

## 3. How to test

```bash
# Increment-5 tests (TC-017 / TC-018)
pytest -q tests/test_tui_directionb.py -k "tc017 or tc018"

# Full directionb + commandbar suites — no regression from increment 4
pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py

# Full suite — must not regress from 308 passed / 2 skipped / 3 xfailed / 0 failed
pytest -q

# App still imports with the re-laid-out Workspace
python -c "import s19_app.tui; print('import OK')"

# py_compile substitute for ruff (ruff is not installed — see Test results)
python -m py_compile s19_app/tui/app.py tests/test_tui_directionb.py
```

`App.run_test()` increment-5 smoke (run during dev — see Test results §4):
parse the public `examples/case_00_public/prg.s19` fixture, build a
`LoadedFile` via `build_loaded_s19`, mount `S19TuiApp` at 120×30 / 160×40 /
80×24, assign `current_file`, call `update_sections` / `update_hex_view` /
`update_a2l_view`, and assert the three panes render, are ordered
left-to-right, and match the LLR-008.1 width tolerances in both regimes.

## 4. Test results (actual output)

**`pytest -q tests/test_tui_directionb.py -k "tc017 or tc018"`:**
```
......                                                                   [100%]
6 passed, 20 deselected in 3.44s
```
6 new increment-5 cases: TC-017 ×3 (fixed regime 120×30+160×40, pane order, proportional regime 80×24), TC-018 ×3 (panes populate, caps unchanged, output bounded).

**`pytest -q tests/test_tui_directionb.py tests/test_tui_commandbar.py`:**
```
.......................................                                 [100%]
39 passed in 33.70s
```
26 directionb (20 increments 2-4 + 6 increment-5) + 13 commandbar. No prior case regressed.

**`pytest -q` (full suite):**
```
314 passed, 2 skipped, 3 xfailed in 146.72s (0:02:26)
```
0 failed. Increment-4 baseline was 308 passed / 2 skipped / 3 xfailed / 0 failed; the +6 are exactly the new increment-5 cases. The 2 skipped + 3 xfailed are unchanged (pre-existing). No test was silently skipped. The pre-batch `test_tui_app.py` UI suite passes unchanged — a grep confirmed no test queries the removed container ids (`#main_layout` / `#status_panel` / `#files_panel` / `#sections_panel` / `#hex_panel` / `#a2l_panel`); the one match for `a2l_panel` is a test *method name*, not a `query_one`.

**`App.run_test()` increment-5 fixture-load smoke (real `prg.s19`):**
```
size=(120, 30) regime=fixed       body=96  rail=22 left=22 center=34 right=40
  panes ordered L<C<R: True  sections=11 hex=True context=True
size=(160, 40) regime=fixed       body=136 rail=22 left=22 center=74 right=40
  panes ordered L<C<R: True  sections=11 hex=True context=True
size=(80, 24)  regime=proportional body=74  rail=4  left=17 center=35 right=22
  panes ordered L<C<R: True  sections=11 hex=True context=True
```
With the public `prg.s19` fixture loaded, all three panes render and are ordered ranges/sections < hex < context at every size. Width regimes match LLR-008.1:
- **120×30 / 160×40 (fixed):** rail 22, left 22 (22±2 ✓), right 40 (40±2 ✓), center the `1fr` remainder (34 / 74, strictly positive ✓).
- **80×24 (proportional):** rail collapsed to 4 (4±1 ✓), left 17 = 23.0% of body (24%±3 ✓), right 22 = 29.7% (30%±3 ✓), center 35 strictly positive (no clip ✓).
- 119×30 boundary spot-check during dev: proportional regime active at 119, fixed at 120 (the 119/120 breakpoint check is formally verdicted by TC-016 in increment 12).

**`py_compile`:** `app.py`, `test_tui_directionb.py` compile clean.

**`ruff check .` / `ruff format --check .`:** **NOT RUN — ruff is not installed in this environment** (`ModuleNotFoundError: No module named 'ruff'`). As the increment brief directs, `python -m py_compile` was run on both changed Python files as the substitute — all compile clean. `styles.tcss` is loaded and parsed by the Textual engine in every `run_test()`-based case (39 directionb/commandbar cases + the full suite exercise it); a malformed rule would surface as a `StylesheetError` at mount. Recommend running `ruff check .` in CI / a ruff-equipped environment before merge.

## 5. Risks

- **Carry-over container is a deliberate temporary scaffold.** `#workspace_carryover` keeps the Issues table + status/log widgets in the Workspace tree (hidden) only because increment 7 has not yet re-homed them and the renderers (`update_validation_issues_view`, `update_project_labels`, `set_status`, the log tail, `#progress_bar`, the `issues_filter_*` handlers) still target those ids. This is the minimal way to honor "drop those cleanly without orphaning a renderer" (increment-plan §3 / increment-5 Key risks) without modifying a renderer (C-1). **Increment 7 must dismantle `#workspace_carryover`** — promote `#validation_issues_list` / filters / summary into `#screen_issues`, and re-home `#status_text` / `#progress_bar` / `#log_line_*` to the persistent footer/status-bar area. Until then those widgets are present-but-invisible; `update_project_labels` still double-writes `#project_text` / `#a2l_text` (carry-over) and the command bar (increment 4) — harmless, the carry-over copies are not displayed.
- **Fixed-regime CSS chrome math.** The `>= 120` regime uses fixed columns: rail 22 + left 22 + right 40 = 84 columns of chrome, with the center hex pane taking the `1fr` remainder. At the 120-column minimum of the fixed regime the workspace body is ~96 columns and the center pane lands at 34 columns — positive and non-clipping, confirmed by TC-017 and the smoke. Below 120 the proportional regime takes over and the rail collapses, so the 84-column fixed chrome never coexists with an 80-column terminal.
- **Increment-3 latent rail-collapse defect — fixed here.** The `#workspace_body.width-narrow #rail_slot` selector shipped in increment 3 never matched (sibling, not descendant); the rail did not collapse at `< 120` columns. Fixed by toggling `width-narrow` on `#workspace_shell` too and re-keying the rule. The increment-2/3 tests assert `width-narrow` on `#workspace_body` and still pass (the class is set on both). A2L (increment 6) and any later screen relying on rail collapse now get a correctly-collapsing rail for free.
- **`MAX_HEX_BYTES` ≠ `HEX_WIDTH * MAX_HEX_ROWS`.** The actual pre-batch caps are `HEX_WIDTH=16`, `MAX_HEX_ROWS=512`, `MAX_HEX_BYTES=65536` (= 16×4096), `FOCUS_CONTEXT_ROWS=64` — the byte cap is the looser of the two, so the 512-row cap governs first for the TC-018 over-cap fixture. TC-018 pins all four to their literal pre-batch values; the increment changed none of them (it touches no `hexview.py`).
- **`Static.content` access in tests.** TC-018 reads `#hex_view` / `#a2l_view` text via `str(widget.content)` (the Textual `Content` object) — `Static` exposes no `.renderable`. This matches the increment-4 command-bar tests' `str(bar.query_one(...).content)` pattern. If a future Textual version changes the `Static` content API the assertion locator (not the intent) would need updating.
- **Pane widths verified via `region.width`.** TC-017 reads `app.query_one(...).region.width` after `pilot.pause()`, the same harness pattern the increment-plan TC-017 row specifies. Width values are post-layout actuals, so the ±2-column / ±3-point tolerances absorb border/padding rounding exactly as LLR-008.1's rationale intends.

## 6. Pending items

- **Increment 7 must dismantle `#workspace_carryover`** — promote the Issues `DataTable` + `validation_issues_filters` + `validation_issues_summary` into `#screen_issues`, and re-home `#status_text` / `#progress_bar` / `#log_line_1..4` to the persistent footer/status-bar area, so no renderer is left writing into a dead container. This is the explicit increment-7 dependency (increment-plan §3, increment 7 "Key risks": grep `status_text` / `progress_bar` / `log_line_` before editing).
- **`ruff check` / `ruff format --check` not executed** — ruff absent from this environment; must run in CI / a ruff-equipped environment before merge.
- **119/120-column boundary check (CV-04)** — TC-017 here asserts the fixed regime at 120×30/160×40 and the proportional regime at 80×24; the explicit 119-vs-120 breakpoint assertion is implemented in increment 12 per the increment-plan. A dev spot-check confirmed proportional at 119 / fixed at 120.
- **Workspace empty-state (LLR-002.3) for the re-laid-out screen** — increment 2's TC-037 scope note defers the Workspace empty-state integration to the per-screen re-layout. This increment lays out the three panes but does not add an `EmptyStatePanel` to `#screen_workspace`; the no-file Workspace currently shows empty panes. If LLR-002.3 requires the Workspace to show the empty-state panel, that wiring is a small follow-up — flag for the increment-11 keyboard/reachability sweep or a dedicated note. (Not in the increment-5 LLR set: increment 5 covers LLR-008.1 / LLR-008.2 only.)
- **Snapshot baselines (increment 12)** — the Workspace 3-pane layout under {compact, comfortable} × {80×24, 120×30, 160×40} is verdicted by the increment-12 snapshot matrix; the `.db-pane` density padding swap is exercised but not yet snapshot-pinned.

## 7. Suggested next task

**Increment 6 — A2L Explorer + MAC View re-layout** (LLR-009.1, LLR-009.2, LLR-010.1, LLR-010.2). Re-compose `#screen_a2l` and `#screen_mac` from the pre-batch `#alt_layout` / `#mac_layout` grids into the Direction B two-regime layout: a `1fr` `DataTable` pane + a fixed-40 / proportional-35% hex pane, mirroring the increment-5 two-regime CSS pattern (the collapsed-rail rule is now correct and shared). Re-point `update_a2l_tags_view` / `_filter_a2l_tags` / `update_mac_view` / `update_mac_hex_view` and the A2L/MAC paging actions to the new container ids without modifying the renderers or the filter/paging/jump logic (C-1 / LLR-009.2 / LLR-010.2); the A2L and MAC hex panes reuse the existing `#alt_hex_view` / `#mac_hex_view` subtrees verbatim so their goto handlers are unchanged. A2L is the highest-regression-risk area (`R-A2L-*` / `R-TUI-018/019/020`) — TC-020 / TC-022 re-run the existing A2L/MAC behavior tests against the restyled screens.

---

*Increment 5 complete. Stopping at the increment boundary — increment 6 is NOT started.*
