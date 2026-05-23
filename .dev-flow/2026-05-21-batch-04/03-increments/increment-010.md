# Increment 010 — Patch Editor scrollability fix (batch-04, Phase 3)

Corrective increment from user review feedback on the running app.

## 1. What changed

The Patch Editor rail screen (rail key 6) overflowed the terminal and clipped
its lower content — the memory-change half, the unified-file row and the
`Export` button were unreachable because `PatchEditorPanel` was a plain
`Container` (no scroll) holding two `1fr` `DataTable`s plus several stacked
input/button rows that together exceed any normal terminal height.

`PatchEditorPanel` now subclasses `textual.containers.ScrollableContainer`
(the established Direction B idiom — `app.py` already uses it for the hex and
A2L panes), so the whole stacked Patch Editor content scrolls vertically and
every control stays reachable. The two `DataTable`s are bounded to a fixed
`height: 10` (each keeps its own internal row scroll for long lists) so the
scroll-container layout is well-defined instead of two competing `1fr`
regions that would push the input/button rows off-screen. The
`#patch_editor_panel` CSS rule was split out from the shared
`#ab_diff_panel` rule and given an explicit `overflow-y: auto`. No engine,
service, `cdfx/` package or `app.py` logic was touched — this is a view-layer
container/CSS change plus a test and the one regenerated snapshot baseline.

## 2. Files modified

| File | Purpose of change |
|------|-------------------|
| `s19_app/tui/screens_directionb.py` | Import `ScrollableContainer`; change `PatchEditorPanel` base class from `Container` to `ScrollableContainer`; update the class + `compose` docstrings to describe the scroll behaviour. |
| `s19_app/tui/styles.tcss` | Split `#patch_editor_panel` out of the shared `#ab_diff_panel` rule and add `overflow-y: auto`; change `#patch_changelist_table` / `#patch_memory_table` from `height: 1fr` to a bounded `height: 10`. |
| `tests/test_tui_memory_patch.py` | Add `test_patch_editor_panel_scrolls_to_reach_export_button` — drives a real `S19TuiApp` via `App.run_test()`, asserts the panel is a `ScrollableContainer`, has a positive `max_scroll_y` at 120x30, and that scrolling brings `#patch_export_button` into the visible region. |
| `tests/__snapshots__/test_tui_snapshot/test_tc016s_density_layout_snapshot[patch-comfortable-120x30].svg` | Regenerated baseline — the Patch Editor layout changed (bounded tables + scroll). Only this one baseline regenerated. |

File count: 4 (cap is 5).

## 3. How to test

```bash
# Compile + import sanity (ruff not installed — py_compile substitute)
python -m py_compile s19_app/tui/screens_directionb.py tests/test_tui_memory_patch.py
python -c "import s19_app.tui"

# The new scroll test
pytest -q tests/test_tui_memory_patch.py::test_patch_editor_panel_scrolls_to_reach_export_button

# All Patch Editor tests
pytest -q tests/test_tui_memory_patch.py tests/test_tui_patch_editor.py

# Snapshot suite (the patch baseline was regenerated)
pytest -q -m snapshot

# Full suite
pytest -q
```

`App.run_test()` smoke (drives the patch screen, scrolls to the Export
button): see Test results below.

## 4. Test results (actual output)

`python -m py_compile ...` → `PY_COMPILE_OK`
`python -c "import s19_app.tui"` → `IMPORT_OK`

New scroll test:
```
1 passed in 0.58s
```

All Patch Editor tests (`test_tui_memory_patch.py` + `test_tui_patch_editor.py`):
```
44 passed in 16.44s
```

Snapshot suite (patch baseline regenerated, then re-verified):
```
# --snapshot-update run
1 snapshot updated.
1 passed, 767 deselected in 0.97s
# clean verification run
27 snapshots passed.
27 passed, 741 deselected in 25.99s
```

Full suite:
```
763 passed, 2 skipped, 3 xfailed in 200.84s
```
Baseline was 762 passed / 2 skipped / 3 xfailed / 0 failed; now 763 passed
(+1 = the new scroll test), 0 failed. Baseline holds.

`App.run_test()` smoke output:
```
panel is ScrollableContainer: True
max_scroll_y (content overflows viewport): 52
export button present in tree: patch_export_button
export visible after scroll: True
SMOKE_OK
```

## 5. Risks

- **Bounded table height (`height: 10`)** is a fixed value, not adaptive. On
  a very tall terminal there is extra empty space below the 10-row tables;
  on a very short one the table itself scrolls internally. Both are correct
  behaviour, but the value is a layout judgement call — if reviewers prefer
  a different number (`12` etc.) it is a one-line CSS change.
- **Nested scroll regions**: each `DataTable` scrolls internally and the
  panel scrolls as a whole. Mouse-wheel focus determines which scrolls.
  This is standard Textual behaviour and matches how the hex pane already
  works, but it is a minor UX nuance.
- **Snapshot baseline**: only `patch-comfortable-120x30` was regenerated. If
  any other density/size variant of the patch screen existed it would now be
  stale — none do (the snapshot dir has exactly one `patch-*` baseline), so
  no risk, but noted for completeness.
- No data-processing path changed, so no parser/engine/service regression
  surface is touched.

## 6. Pending items

None for this increment. The defect (clipped, non-scrolling Patch Editor) is
resolved: the panel scrolls and `#patch_export_button` plus the memory half
are reachable, confirmed by an automated test and a live `App.run_test()`
smoke.

## 7. Suggested next task

Consider a brief manual pass over the *other* rail screens at a short
terminal (e.g. 120x24) to confirm none of them silently clip content the
same way the Patch Editor did — the Memory Map and A2B Diff panels are also
`Container`-based. If any overflow, give them the same `ScrollableContainer`
treatment as a follow-up corrective increment.
