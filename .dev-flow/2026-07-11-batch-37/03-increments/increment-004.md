# Increment 004 — US-063 (B-13) Entropy band legend + clickable strip

> Batch-37 · Inc-4 · Scope = **US-063 only** (HLR-063 / LLR-063.1/.2/.3).
> Base = batch-37 working tree carrying Inc-1 + Inc-2 + Inc-3 (untouched).
> Ledger base = 1377 → post = 1381 (+4 AT/TC, 0 deletions).

## 1. What changed

Added two operator affordances to the entropy-viewer modal (`EntropyViewerScreen`):

- **Band-colour legend (LLR-063.1):** a new `#entropy_legend` container renders
  one row per `ENTROPY_BAND_COLOUR` band (a coloured `█` swatch + the band label
  + its plain-language meaning) plus one row documenting the low-confidence
  `dim` cue. The rows are **derived** by iterating `ENTROPY_BAND_COLOUR` (the
  single source) and looking each band's meaning up in a new sibling
  `ENTROPY_BAND_MEANING` map — NOT hardcoded, NOT drawn from the severity
  `legend.py::LEGEND_TABLE` (a different colour domain, D-063). The legend is
  window-independent (renders for an empty image too). Meanings are authored
  free of `[` / `]` (S-03) and each row is a Rich `Text` object (not a markup
  string), so a markup-enabled render cannot misparse them.

- **Click-navigable strip — rung-2 BASELINE (LLR-063.2, Q-03/A-05):** the strip
  `#entropy_strip` changed from a single plain `Static` to a `Horizontal` of
  per-cell clickable `EntropyCell` widgets, one per window on the current page,
  each with a deterministic `#entropy_cell_<row>` id. A real pointer click posts
  `EntropyCell.Selected(row)`; the screen routes it to the new `action_jump(row)`
  sink, which resolves the row through the **shared** `(sort, page, row) → window`
  helper `_window_for_row` (LLR-062.2, same helper the jump list uses) and
  dismisses with that window's `start` address. `action_jump` preserves the
  `0 <= row < len(page slice)` bound (S-03) so a click on padding beyond the last
  cell is a safe no-op. `on_list_view_selected` was refactored to call
  `action_jump` too, so the list and click paths share one navigation sink.

The Rich `@click`-meta offset alternative on a single wrapped `Static` (former
rung-1) was NOT built — it stays a demoted optional spike (D-063, Q-03/A-05).

## 2. Files modified (4 — within the ≤5 cap)

| File | Change |
|------|--------|
| `s19_app/tui/screens.py` | `+from textual.events import Click`; new `ENTROPY_BAND_MEANING` map; new `EntropyCell(Static)` widget (+`Selected` message + `on_click`); `EntropyViewerScreen`: `LOW_CONFIDENCE_MEANING` const, `_strip_cells`/`_legend_lines`/`_legend_widget` helpers, `compose` (Horizontal cell strip + legend), `_refresh_view` (remount cells via `call_after_refresh`), new `action_jump` + `on_entropy_cell_selected`, `on_list_view_selected` → `action_jump` |
| `s19_app/tui/styles.tcss` | `#entropy_strip` (`width:100%; overflow-x:auto`), new `.entropy-cell` (1×1), new `#entropy_legend` (auto height, padding) |
| `tests/test_tui_entropy_viewer.py` | +AT-063a, +AT-063b, +TC-326, +TC-327; geometry helper strip query `Static`→id-only (widget-type supersession); dropped now-unused `Static` import |
| `tests/test_tui_snapshot.py` | extended `_batch37_entropy_drift_marks` reason to name US-063 legend + per-cell strip |

Both changed source modules are **non-frozen** (screens.py / styles.tcss);
`entropy_service` and the engine set are untouched.

## 3. How to test

```
pytest tests/test_tui_entropy_viewer.py -q
pytest tests/test_tui_snapshot.py -q -k entropy      # expect 2 xfailed
pytest tests/test_tui_snapshot.py -q                 # no NEW failures
pytest tests/test_engine_unchanged.py -q             # frozen guard
pytest tests/test_tui_directionb.py -q -k tc031      # frozen guard
python -m ruff check s19_app/tui/screens.py tests/test_tui_entropy_viewer.py tests/test_tui_snapshot.py
```

## 4. Test results (real output)

- **RED (C-20, pre-change, editing-in-place):** `pytest -k "at063 or tc326 or tc327"`
  → **4 failed** — `AttributeError: 'EntropyViewerScreen' object has no attribute
  '_legend_lines'`; `action_jump` = `None` (not callable); `#entropy_legend`
  `NoMatches`; `#entropy_cell_k` absent. Captured before implementation.
- **GREEN:** `pytest tests/test_tui_entropy_viewer.py -q` → **21 passed** (17
  existing incl. Inc-3 AT-062a/b, TC-324/325, TC-036.5 + 4 new). Exit 0.
- **AT-063b `pilot.click` proof (C-16):** `_drive_click("#entropy_cell_0")` →
  `app._goto_focus_address == 0x1200` (max-entropy under `entropy` sort);
  `_drive_click("#entropy_cell_1")` → `0x1100` (last cell of the page). A REAL
  `await pilot.click(...)`, never a proxy call to `action_jump`.
- **Snapshot:** `-k entropy` → **2 xfailed** (the two entropy cells, expected
  drift); full `test_tui_snapshot.py` → **32 passed, 2 xfailed** — no NEW failure.
- **Frozen guards:** `test_engine_unchanged.py` 1 passed; `test_tui_directionb.py -k tc031`
  7 passed — **0 diffs**.
- **Ruff:** clean (`All checks passed!`).
- **Inc-1/2 shared-file regression:** `test_tui_patch_editor_v2.py` +
  `test_before_after_report.py` → **55 passed** (screens.py change did not
  disturb the patch editor / before-after paths).
- **Ledger:** `pytest --collect-only -q` → **1381** (= 1377 − 0 + 4). Entropy
  file = 21 nodes.

### Evidence checklist
- [x] Tests/type checks/lint pass — 21/21 entropy GREEN; ruff clean; frozen 0 diffs.
- [x] No secrets in code or output.
- [x] No destructive commands run.
- [x] File count within cap — 4 files.
- [x] Review packet attached (this file).

## 5. C-23 geometry (PILOT-MEASURED, not fr-estimated)

Measured via `App.run_test(size=…)` over the 2-window MIXED image, reading real
`.region` / `.content_region`:

| Width | body content | strip (right) | legend (right, rows) | cells | overflow? |
|-------|--------------|---------------|----------------------|-------|-----------|
| **80x24** | x16 y6 → right64 bottom15 (w48 h9) | right **62** ≤ 80, h1 | right **62** ≤ 80, 5 labels (y12–16) | `cell_0` x16→17, `cell_1` x17→18 (both visible, y10) | **none** |
| **120x30** | x22 y6 → right98 bottom21 (w76 h15) | right **98** ≤ 120, h1 | right **98** ≤ 120, 5 labels (y12–16) | `cell_0` x22→23, `cell_1` x23→24 (y10) | **none** |

- **No horizontal overflow** at either width (strip & legend `right` within the
  terminal, dialog `right` ≤ W — matches the existing LLR-036.3 geometry tests
  which still pass).
- **Legend fit:** fully in-viewport at **120x30** (5 rows within the 15-row
  body). At **80x24** the body shows ~9 rows so the last ~2 of the 5 legend rows
  sit below the fold and are **scroll-reachable** via `#entropy_body`
  `overflow-y: auto` — LLR-063.3 permits "visible **or** scroll-reachable".
  Measured deficit at 80x24: body height 9 vs. legend (5) + strip (1) + controls
  (1) content → the tail scrolls; **no clipping, no compact form required**
  because the acceptance is scroll-reachability + no horizontal overflow, both met.
- **Per-cell strip fits at both widths** (1-col cells, left-aligned, within the
  46/76-col content budget); the AT drives small fixtures so all clicked cells
  are on-screen. For a full 512-window page the tail cells are horizontally
  scroll-reachable (`overflow-x: auto`) — reachability is also served by the
  jump list + paging.

## 6. Per-LLR coverage

- **LLR-063.1 (legend, single source):** `_legend_lines` iterates
  `ENTROPY_BAND_COLOUR`; `ENTROPY_BAND_MEANING` supplies meanings; TC-326 pins
  `set(ENTROPY_BAND_MEANING) == set(ENTROPY_BAND_COLOUR)` + non-blank + no
  `[`/`]` + no `sev-`. AT-063a asserts all four band meanings + the dim cue in
  the rendered `#entropy_legend Label`s.
- **LLR-063.2 (rung-2 per-cell click, C-16):** `EntropyCell` widgets with
  `#entropy_cell_k` ids; `action_jump` → shared `_window_for_row` remap →
  dismiss; S-03 bound preserved. AT-063b drives a real `pilot.click` under a
  non-default (`entropy`) sort + shrunken page budget and asserts the exact
  dismissed address for first & last cell. TC-327 white-boxes the remap under
  address/entropy sort + page 0/1 and the out-of-range/None no-op.
- **LLR-063.3 (geometry, C-23):** pilot-measured at 80x24 + 120x30 (§5);
  existing `test_geometry_fits_80/120` still green under the new widget type.

## 7. Risks · Pending · Next

**Risks (low):**
- Per-cell widgets are bounded at ≤ 512 per page (accepted in LLR-063.2/D-063);
  mounting a full 512-cell page is heavier than the prior single `Static`. The
  large-image Inc-3 nodes (AT-062a) still pass; no timeout observed.
- `_refresh_view` remounts strip cells via `call_after_refresh` (prune-then-mount)
  to avoid a transient duplicate-id collision on the reused `#entropy_cell_k`
  ids; verified GREEN across sort/page toggles (AT-062a/b, AT-063b).

**Supersession (recorded):** the batch-26 geometry helper `_modal_dialog_right`
queried `#entropy_strip` as a `Static`; the strip is now a `Horizontal` of
cells, so the query is id-only (type-agnostic). The assertion (region within the
terminal width, LLR-036.3) is unchanged — a forced type update, not a semantic
change.

**Snapshot disposition (C-22):** the two entropy cells
(`entropy-comfortable-80x24` / `-120x30`) remain `xfail(strict=False)` — Inc-4
drifts them further (legend rows + per-cell strip); the drift-mark reason was
extended to name US-063. **No local baseline regen** (canonical-CI only,
snapshot-regen convention). Full `test_tui_snapshot.py` = 32 passed, 2 xfailed,
no NEW failure.

**Pending:** none for US-063. **C-18:** each AT/TC is exactly one on-disk node
(AT-063a, AT-063b, TC-326, TC-327 — 4 nodes; AT-063b/AT-062x internally loop
sizes/cells within the single node).

**Suggested next task:** Inc-5 = US-064a (patch-editor refresh) or US-064b (JSON
popup), per the batch-37 plan. REQUIREMENTS.md `R-TUI-051` (US-063) to be marked
`Automated` at batch close.
