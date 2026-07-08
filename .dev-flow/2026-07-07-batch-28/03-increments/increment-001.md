# Increment 001 — US-038 A2L Explorer table polish (LLR-042.1 + LLR-042.2)

Batch-28 · R-TUI-042 · Direction A · TUI render-side only.

## 1. What changed
- **LLR-042.2 (build) — compact density.** The A2L tags pane now carries a
  queryable `density-compact` class and the `#a2l_tags_list` DataTable renders
  with `cell_padding=0`, mirroring the existing `#workspace_body.density-compact`
  precedent. A new `#a2l_tags_pane.density-compact` CSS rule tightens the pane
  padding (`.db-pane` base `padding: 1` → `0 1`).
- **LLR-042.1 (verify-not-build) — fixed header.** **Finding: the header was
  already fixed.** Textual's `DataTable` owns its own row scrolling and keeps the
  column header row pinned by default — no machinery was added. The behaviour is
  now *locked by a test* (AT-038a / TC-042.1) that drives a REAL `pagedown` and
  asserts the DataTable's `scroll_offset.y` advanced while the outer `#a2l_tags_pane`
  / `#screen_a2l` containers stayed at `scroll_offset.y == 0` (i.e. the DataTable —
  not an outer container — is the scroll owner, so the header cannot scroll away).
  The `#a2l_scroll` container cited in the draft is the Workspace context pane
  (`#a2l_view`), unrelated to the tags DataTable — confirmed, no change there.
- **Severity colouring + paging + `Text` cells UNCHANGED.** `_severity_style`
  per-row colouring (app.py:7895-7896) and the `_a2l_window_start` paging path are
  untouched; cells remain `rich.text.Text` (no `markup=False`→True flip —
  batch-27 B-1 regression class).
- **Tests added** (6 test functions) in `tests/test_tui_directionb.py`:
  AT-038a (`test_at_038a_a2l_table_owns_scroll_header_fixed`, also carries TC-042.1),
  AT-038b (`test_at_038b_a2l_pane_carries_density_compact_class`),
  AT-038c (`test_at_038c_a2l_error_row_keeps_severity_style`),
  AT-038d (`test_at_038d_a2l_empty_state_no_file`),
  TC-042.2 (`test_tc_042_2_density_class_text_cells_and_paging`),
  plus a shared `_a2l_enriched_case_01` helper.
- **Snapshot cells** for the A2L screen (6 cells: `a2l-{compact,comfortable}-{80x24,120x30,160x40}`)
  marked **xfail-until-baseline** via a new `_restyled_cell_marks` helper — the
  density polish shifts the SVG; local regen is FORBIDDEN (textual pinned 8.2.8;
  canonical-CI `snapshot-regen.yml` only), same batch-25/27 pattern.

### Surface correction (flagged)
The requirement draft's AT-038a says `press("3")` to open A2L. Verified against
`app.py:687-691`: key **"2"** opens the A2L Explorer; **"3"** is MAC View. The ATs
drive the real A2L key **"2"** — the draft named the wrong surface.

## 2. Files modified (4 code/test + this packet = 5, within cap)
- `s19_app/tui/app.py` — `_compose_screen_a2l`: `DataTable(..., cell_padding=0)`;
  pane `classes="db-pane density-compact"`; docstring note.
- `s19_app/tui/styles.tcss` — new `#a2l_tags_pane.density-compact { padding: 0 1; }` rule.
- `tests/test_tui_directionb.py` — +6 tests + `_a2l_enriched_case_01` helper.
- `tests/test_tui_snapshot.py` — `_restyled_cell_marks` helper; A2L cells xfail-until-baseline.
- `.dev-flow/2026-07-07-batch-28/03-increments/increment-001.md` — this packet.

**Engine-frozen set: 0 diffs** (no edits to `core.py`, `hexfile.py`, `range_index.py`,
`validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`).

## 3. How to test
```bash
# New AT/TC (Layer A + B)
python -m pytest tests/test_tui_directionb.py -k "038 or 042_2" -q
# Engine-frozen guard
python -m pytest tests/test_engine_unchanged.py -q
# Snapshot A2L cells resolve as xfail (not hard-fail); needs pytest-textual-snapshot
python -m pytest tests/test_tui_snapshot.py -q -k "a2l"
# Lint
python -m ruff check s19_app/tui/app.py tests/test_tui_directionb.py tests/test_tui_snapshot.py
```

## 4. Test results (real output)
- `pytest -k "038 or 042_2"` → **6 passed, 124 deselected in 5.40s**.
- `tests/test_tui_directionb.py` full → **130 passed in 86.60s**.
- `tests/test_engine_unchanged.py` → **1 passed** (0 engine-frozen diffs).
- `tests/test_tui_snapshot.py -k a2l` → **6 xfailed, 28 deselected** (expected
  mismatch until canonical-CI baseline regen — not a hard failure).
- `ruff check` (app.py + both test files) → **All checks passed!**

### Evidence checklist
- [✓] Tests/type checks/lint pass — pytest 6/130 pass; ruff clean (above).
- [✓] No secrets in code or output — render-only CSS/DataTable change.
- [✓] No destructive commands run — none.
- [✓] File count within cap — 4 code/test + packet = 5.
- [✓] Review packet attached — this file.

## 5. Risks
- **Snapshot drift (contained):** the density change shifts all 6 A2L baselines;
  they are xfail-until-baseline and MUST be regenerated in canonical CI
  (`snapshot-regen.yml`, textual==8.2.8) post-merge, then the xfail marks retired
  (drop `_restyled_cell_marks`'s A2L branch). Local regen is FORBIDDEN.
- **AT-038a data shape:** case_01 has only 3 A2L tags — too few to overflow the
  pane — so the scroll AT repeats the *real* case_01 enriched tag to a 180-row
  window through the real `update_a2l_tags_view` renderer purely to give the table
  something to scroll. The scroll itself (`pagedown` → `scroll_offset.y`) is the
  real mechanism under test (C-16); the data volume is scaffolding, not a mock of
  the mechanism.
- **Draft `press("3")` error:** corrected to `"2"` in the ATs; the requirement text
  should be amended to match (surfaced above).

## 6. Pending items (this batch, later increments)
- US-039 Issues grouped-dense (LLR-042.3/.4/.5/.6/.10 — incl. C-17 hostile AT-039e).
- US-040 Workspace signal (LLR-042.7 micro-bar / .8 memory strip / .9 stat pane).
- Post-merge: canonical-CI A2L snapshot regen + retire the A2L xfail branch.
- Amend requirement §5.2 / AT-038a text: `press("3")` → `press("2")`.

## 7. Suggested next task
Increment 2 — **US-039 Issues grouped-by-severity dense view** (LLR-042.3/.4/.10,
plus the C-17 mandatory hostile-input AT-039e over the new `.code` chip markup
surface and the AT-039f large-N bounded-mount guard). Issues is the higher-risk,
markup-bearing direction and per §6.2 should land before Workspace.

---
**Test-count delta:** tests/test_tui_directionb.py 124 → 130 (+6). Snapshot suite:
0 new cells added; 6 existing A2L cells flipped green → xfail-until-baseline.
