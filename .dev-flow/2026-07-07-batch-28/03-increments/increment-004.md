# Increment 004 (final) — US-040b Workspace whole-image memory strip

Batch-28 · R-TUI-042 · Direction B · TUI render-side only.
LLR-042.8 (whole-image memory strip) · LLR-042.11 close (geometry / empty-state
across the new Workspace surfaces) · LLR-042.12 (engine-frozen invariant) ·
+ two Inc-3 LOW cleanups (F1 geometry-gate `#a2l_scroll`, F2 redundant `int()`).

**Phase 3 COMPLETE — all US-038/039/040 shipped, R-TUI-042 LLRs .1–.12 covered.**

## 1. What changed
- **LLR-042.8 — whole-image memory strip.** A new single-row `#ws_memstrip`
  band composed ABOVE `#workspace_panes` inside `#screen_workspace` (spans the
  workspace body width, so it does NOT steal the fixed 22-col `#ws_left`
  budget). A new renderer `S19TuiApp.update_memory_strip()`:
  - **Cells / colour derive** from the already-computed
    `current_file.ranges` / `range_validity` only — no new parse/coverage/
    validation. It builds `(start, end, is_valid)` triples, derives the image
    span (`derive_image_span`), and for each cell computes `cell_status(...)` →
    `status_to_css_class(...)` — the **frozen-safe batch-27 minimap path**
    (valid→`sev-ok`, invalid→`sev-error`, gap→`sev-neutral`; colour exclusively
    via `css_class_for_severity`, no hard-coded hex). Each cell is a
    `Static(safe_text("█"), classes="strip-cell sev-*")` (markup-safe).
  - **Bounded cell cap.** The cell count is
    `cell_count_for_geometry(span, band_width, 1)` (rows=1 variant) where
    `band_width` is the band's measured `content_size.width` (fallback
    `WORKSPACE_MEMSTRIP_DEFAULT_COLS = 76` pre-layout). A hostile huge image is
    capped at the band width (≤ ~98 cells at 120 cols), never O(image size).
  - **Empty state.** No file / empty ranges / zero span → the band is cleared
    (no cells, neutral blank band, no crash).
  - **Workspace-only.** The strip is composed solely inside `#screen_workspace`;
    other rail screens carry no `#ws_memstrip` node.
  - Called from the top of `update_sections()` (the batch's canonical post-load
    refresh) so it refreshes on every load and on the no-file clear.
- **LLR-042.11 — geometry / empty-state closed.** `#workspace_panes` height
  changed `100%` → `1fr` so the 1-row strip band (+1 row `margin-bottom`, ≤2
  rows total, C-13 batch-17 mode) takes the top and the panes take the
  remainder — the `#ws_center` hex view still renders ≥1 row at 80×24. The
  geometry gate (below) proves positive area for every pane + hex + strip at
  80×24 and 120×40. Each new surface (micro-bar, stat pane, strip) has a neutral
  no-file state.
- **LLR-042.12 — engine-frozen invariant.** 0 diff on any frozen path; the
  standing guards stay green (see §4). All strip logic is in `app.py` +
  reused `screens_directionb` public helpers (neither frozen).
- **Inc-3 LOW cleanups folded in:**
  - **F1** — the Inc-3 geometry gate now also asserts positive area on the
    Context scroll `#a2l_scroll` (and the new `#ws_memstrip`), so a stat-band
    regression that silently shrank the Context pane would be caught.
  - **F2** — dropped the redundant `int(...)` around the already-`int`
    `round(...)` in `coverage_bar_cells` (`max(1, min(width, filled))`).

## 2. Files modified (4 — within the ≤5 cap)
- `s19_app/tui/app.py` — import `derive_image_span` / `cell_count_for_geometry`
  / `bytes_per_cell` / `cell_status` / `status_to_css_class` / `safe_text` from
  `screens_directionb`; new constants `WORKSPACE_MEMSTRIP_DEFAULT_COLS`,
  `_STRIP_CELL_GLYPH`; `#ws_memstrip` band added to the `#screen_workspace`
  compose; new `update_memory_strip()` method + call from `update_sections`;
  F2 cleanup in `coverage_bar_cells`.
- `s19_app/tui/styles.tcss` — `#ws_memstrip` (height 1, horizontal, margin-bottom
  1) + `.strip-cell` (1×1); `#workspace_panes` height `100%` → `1fr`.
- `tests/test_tui_directionb.py` — 6 new tests + 1 helper; extended the Inc-3
  geometry gate in place (F1).
- `tests/test_tui_snapshot.py` — updated the existing `workspace` xfail reason to
  cite the memory strip (the 6 `workspace-*` cells stay xfail-until-baseline;
  NO local regen).

Engine-frozen set (`core.py, hexfile.py, range_index.py, validation/,
tui/a2l.py, tui/mac.py, tui/color_policy.py`) untouched. `screens_directionb.py`
imported read-only (public helpers), not edited.

## 3. How to test
```
python -m ruff check s19_app/tui/app.py tests/test_tui_directionb.py tests/test_tui_snapshot.py
python -m pytest tests/test_tui_directionb.py -k "040 or 042_8 or 042_11 or 042_12 or memstrip or strip" -q
python -m pytest tests/test_tui_directionb.py -k "workspace or sections" -q
python -m pytest tests/test_engine_unchanged.py -q
python -m pytest tests/test_tui_directionb.py -k tc031 -q
python -m pytest tests/test_tui_directionb.py -q          # full suite (no regression)
```

## 4. Test results (all real output)
- `ruff check` (3 changed .py): **All checks passed!**
- New/strip tests `-k "040 or 042_8 or 042_11 or 042_12 or memstrip or strip"`:
  **12 passed**, 142 deselected.
- Regression `-k "workspace or sections"`: **15 passed**, 139 deselected.
- `test_engine_unchanged.py`: **1 passed**. `-k tc031`: **3 passed** (0 frozen diffs).
- `git diff --name-only main -- <frozen set>`: **empty** (0 frozen-path diffs).
- Full `test_tui_directionb.py`: **154 passed** in ~110s (148 base + 6 new; no regression).
- `test_tui_snapshot.py --collect-only`: clean; the 6 `workspace-*` cells keep
  the xfail-until-baseline mark (reason now cites the strip).
- **Geometry (C-13 / TC-042.11):** the extended gate drives `(80,24)` and
  `(120,40)`, loads case_02, renders sections + hex + strip, and asserts
  `#ws_left / #ws_center / #ws_right / #hex_scroll / #sections_list / #ws_stats /
  #a2l_scroll / #ws_memstrip` all have positive area. **PASS at both regimes**
  (hex still ≥1 row at the 80×24 floor).

New tests (6): `test_at040b_memory_strip_valid_and_gap_cells` (AT-040b),
`test_at040b_memory_strip_is_workspace_only`,
`test_at040b_memory_strip_empty_when_no_file`,
`test_at040b_memory_strip_cell_count_is_bounded` (DoS bound),
`test_tc_042_8_strip_colour_is_pure_reuse_of_batch27_helpers` (TC-042.8),
`test_tc_042_12_memory_strip_touches_no_frozen_path` (TC-042.12).
Extended in place: `test_at040_workspace_geometry_no_clip_80_and_120` (TC-042.11 + F1).

Test-count delta: **148 → 154** in `test_tui_directionb.py` (+6). Note: the
Inc-3 packet's "155" line was an internal inconsistency — the Inc-3 run output
itself reported 148 total, which is the true base.

## 5. Risks
- **Snapshot xfail is a promise, not a proof.** The 6 `workspace-*` SVG cells
  stay xfail-until-baseline; they must be regenerated in canonical CI
  (`snapshot-regen.yml`, textual==8.2.8) post-merge, then the xfail dropped
  (batch-25/27 pattern). Local regen is FORBIDDEN.
- **Strip cell count tracks the measured band width.** Because the count reads
  `#ws_memstrip.content_size.width` after layout, headless pre-layout renders
  use the 76-col fallback. Both paths are bounded; the bounded-count test pins
  the cap equals the pure `cell_count_for_geometry` value.
- **Strip span is over ALL ranges (not capped like the section list).** The
  strip covers the whole image span (`derive_image_span`), unlike the
  `#sections_list` which caps rendered rows — this is intentional (whole-image
  minimap) and stays bounded by the band width, not the range count.

## 6. Pending items
- Canonical-CI snapshot regen for the 6 `workspace-*` cells + xfail retirement
  (post-merge).
- REQUIREMENTS.md `R-TUI-042` row + traceability promotion at batch close
  (Phase 6 docs).

## 7. Suggested next task
Batch-28 implementation is COMPLETE (Inc-1 Issues, Inc-2 A2L, Inc-3 Workspace
micro-bar + stat pane, Inc-4 memory strip). Next: **Phase 4 validation review**
(qa/security cross-check of the shipped ATs) → Phase 5 post-mortem → Phase 6
docs (REQUIREMENTS.md R-TUI-042) → PR + canonical-CI snapshot regen + xfail
retirement + `/dev-flow-sync`.

## Evidence checklist
- [x] Tests/type checks/lint pass — ruff clean; 12 strip/040 pass; 154 full-suite pass; engine guard + tc031 pass (evidence §4).
- [x] No secrets in code or output — render-only display arithmetic; no I/O, no credentials.
- [x] No destructive commands run without approval — read/test/git-diff only.
- [x] File count within cap — 4 files (≤5); no new file; `screens_directionb.py` imported read-only.
- [x] Review packet attached — this document.
