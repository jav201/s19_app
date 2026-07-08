# Increment 003 — US-040 Workspace dense-cockpit signal (a)+(c)

Batch-28 · R-TUI-042 · Direction B · TUI render-side only.
LLR-042.7 (per-range coverage micro-bar) · LLR-042.9 (stat pane).
Scope note: the memory strip (LLR-042.8 / US-040b) is a SEPARATE later increment — NOT built here.

## 1. What changed
- **LLR-042.7 — per-range coverage micro-bar (R4 magnitude spark).** Each
  `#ws_left` range row (`update_sections`) gains an **ADDED third line** inside
  its existing `Label` — a fixed-8-cell bar (`SECTIONS_COVERAGE_BAR_WIDTH = 8`)
  of filled (`█`) + empty (`░`) glyphs. Two new pure module functions in
  `app.py`:
  - `coverage_bar_cells(size, max_size, width)` → filled-cell count. Fill width
    is **∝ this range's byte-size relative to the largest rendered range** (a
    relative-magnitude spark, NOT a covered-fraction — a contiguous range is
    100% covered by definition). Largest range → full (8) cells; any non-empty
    range → ≥1 cell; empty/zero-max → 0; monotonic non-decreasing in size.
  - `build_coverage_bar_text(size, max_size, width)` → the bar as a
    `rich.text.Text` (composed markup-safe via `Text.append`, no markup parse —
    batch-27 B-1 discipline). The whole range Label is now built as a `Text`
    (start line / end+size line / bar line).
  - **Colour = validity**, inherited from the row's existing `sev-*` class
    (`css_class_for_severity(OK if valid else ERROR)`) that `update_sections`
    already adds to the Label — valid → `sev-ok`, invalid → `sev-error`. No new
    colour path, no hard-coded severity hex.
  - **No horizontal widening** of the fixed 22-col pane: the bar is 8 cells on
    its own line (well within the ~18 usable cols), added vertically.
- **LLR-042.9 — Workspace stat pane.** `#ws_right` now hosts a `#ws_stats`
  block (a `Static(markup=False)` under a `#ws_stats_title` "Coverage Stats"
  header) **above** the existing Context (`#a2l_view`). A new renderer
  `update_workspace_stats()` fills it via a new pure function
  `build_workspace_stats_text(stats, error_count, warning_count)` showing:
  `Coverage: <pct>%` + `Ranges: <n>` (both from the reused
  `coverage_stats(...)`), `Errors: <e>` + `Warnings: <w>` (severity **tally**
  over `self._validation_issues` — counting, not re-validation). No entropy
  figure (D3 descoped). No-file → neutral `Coverage: —` / `Ranges: 0`.
  `update_workspace_stats()` is called from the top of `update_sections()` so it
  refreshes on every load and on the no-file clear.
- **Integration, not replacement.** The Context pane keeps `#a2l_view`; the
  stat pane sits above it and the Context `ScrollableContainer` takes the
  remaining height (`#ws_right #a2l_scroll { height: 1fr }`).

## 2. Files modified (4 — within the ≤5 cap)
- `s19_app/tui/app.py` — import `coverage_stats`/`CoverageStats`; new pure fns
  `coverage_bar_cells`, `build_coverage_bar_text`, `build_workspace_stats_text`
  + constant `SECTIONS_COVERAGE_BAR_WIDTH`; `update_sections` micro-bar +
  `update_workspace_stats()` call; new `update_workspace_stats` method;
  `#ws_stats`/`#ws_stats_title` added to the `#ws_right` compose.
- `s19_app/tui/styles.tcss` — `#ws_right #ws_stats` (auto height) /
  `#ws_right #a2l_scroll { height: 1fr }`; `#ws_stats_title` added to the shared
  pane-title rule.
- `tests/test_tui_directionb.py` — 7 new tests (TC-042.7, TC-042.9, AT-040a,
  AT-040c, AT-040d, AT-040e, C-13 geometry gate) + 2 read helpers.
- `tests/test_tui_snapshot.py` — `workspace` branch added to
  `_restyled_cell_marks` → the 6 `workspace-*` SVG cells are
  **xfail-until-baseline** (canonical-CI regen post-merge; NO local regen).

Engine-frozen set (`core.py, hexfile.py, range_index.py, validation/,
tui/a2l.py, tui/mac.py, tui/color_policy.py`) untouched.

## 3. How to test
```
python -m ruff check s19_app/tui/app.py tests/test_tui_directionb.py tests/test_tui_snapshot.py
python -m pytest tests/test_tui_directionb.py -k "040 or 042_7 or 042_9" -q
python -m pytest tests/test_tui_directionb.py -k "sections or workspace" -q
python -m pytest tests/test_engine_unchanged.py -q
python -m pytest tests/test_tui_directionb.py -q          # full suite (no regression)
```

## 4. Test results (all real output)
- `ruff check` (3 changed .py): **All checks passed!**
- New tests `-k "040 or 042_7 or 042_9"`: **7 passed**, 141 deselected.
- Regression `-k "sections or workspace"`: **14 passed**, 134 deselected.
- `test_engine_unchanged.py`: **1 passed**. `-k tc031`: **3 passed** (0 frozen diffs).
- Full `test_tui_directionb.py`: **148 passed** (141 pre-existing + 7 new) in ~112s.
- `test_tui_snapshot.py --collect-only`: clean; the 6 `workspace-*` cells carry
  the new xfail mark.
- **Geometry (C-13):** the geometry gate drives `size=(80,24)` and `(120,40)`,
  loads case_02, renders sections + hex, and asserts `#ws_left / #ws_center /
  #ws_right / #hex_scroll / #sections_list / #ws_stats` all have positive area
  (no pane clipped / hex not pushed off). **PASS at both regimes.**

Test-count delta: **148 → 155** in `test_tui_directionb.py` (+7). Snapshot cells
unchanged in count (6 workspace cells flipped to xfail-until-baseline).

## 5. Risks
- **Snapshot xfail is a promise, not a proof.** The 6 `workspace-*` SVG cells
  are xfail-until-baseline; they must be regenerated in canonical CI
  (`snapshot-regen.yml`, textual==8.2.8) post-merge, then the xfail dropped —
  identical to the batch-25/27 pattern. Local regen is FORBIDDEN.
- **Stat-pane counts reflect `_validation_issues` state, not the image.** By
  design (counting, not re-validation) the error/warning tally shows whatever
  the load pipeline has populated into `_validation_issues`. If a caller renders
  sections before validation runs, the tallies show 0 until the next refresh.
  `update_sections` is the batch's canonical post-load refresh, so this matches
  the existing sequencing.
- **Micro-bar `max_size` is over the RENDERED (capped) ranges**, not all ranges
  — consistent with what the pane shows, but a range beyond
  `MAX_SECTIONS_PRIMARY_RANGES` does not influence bar scaling (it is not
  rendered anyway).

## 6. Pending items
- LLR-042.8 / US-040b **whole-image memory strip** — the separate later
  increment (vertical-budget change over `#ws_center`), explicitly out of scope
  here.
- Canonical-CI snapshot regen for the 6 `workspace-*` cells + xfail retirement
  (post-merge).
- REQUIREMENTS.md `R-TUI-042` row + traceability update at batch close.

## 7. Suggested next task
Increment 4 — **LLR-042.8 memory strip** (US-040b): single-row whole-image
minimap band reusing batch-27 `cell_status` / `status_to_css_class` /
`render_ranges` over `ranges`/`range_validity`, Workspace-only, with the
`#ws_center` vertical-budget measurement (C-13 #4) and AT-040b.

## Evidence checklist
- [x] Tests/type checks/lint pass — ruff clean; 7 new pass; 148 full-suite pass; engine guard + tc031 pass.
- [x] No secrets in code or output — render-only display arithmetic; no I/O, no credentials.
- [x] No destructive commands run without approval — read/test only.
- [x] File count within cap — 4 files (≤5).
- [x] Review packet attached — this document.
