# Increment 1 — HLR-033 (US-030 patch-editor 2×2 four-pane split)

> Reparent the ~12-group vertical stack into a 2×2 grid of four panes, shipping WITH its geometry proof. 3 files. **code-reviewer: APPROVE-WITH-NITS** (0 HIGH/MED).

## 1. What changed
`PatchEditorPanel.compose` reparented into 4 pane Containers (`#patch_pane_{entries,changefile,checks,variant}`); `#patch_editor_panel` → `layout: grid; grid-size: 2 3; grid-rows: 1fr 1fr auto`; each pane per-pane vertical scroll; save-back row = `column-span: 2` grid child in the `auto` 3rd row. **R1 fix:** `#patch_doc_controls` → `layout: grid; grid-size: 3` (Textual `Horizontal` doesn't wrap → would clip; the grid flows 5 buttons to 2 rows). All inner ids + actions preserved; `#patch_checks_results > Static` kept direct.

## 2. Files modified (3 of ≤5)
- `s19_app/tui/screens_directionb.py` — compose reparent (panes @:628/:664/:719/:731; save-back span @:734).
- `s19_app/tui/styles.tcss` — panel grid @:556; `#patch_pane_*` scroll; save-back `column-span:2`; `#patch_doc_controls grid-size:3`.
- `tests/test_tui_patch_layout.py` — NEW: AT-033a/b/c + white-box TC.

## 3. How to test
```
python -m pytest tests/test_tui_patch_layout.py -q
python -m pytest tests/test_tui_patch_editor_v2.py -q   # reparent-safety net (26 tests)
python -m pytest -q -m "not slow"
python -m ruff check s19_app/tui/screens_directionb.py tests/test_tui_patch_layout.py
```

## 4. Test results
- AT-033a (80×24) / AT-033b (120×30) GREEN — 2×2 (2 distinct region.x + 2 distinct region.y, **each row/col band exactly 2 panes** — L-shape rejected), each `region.width ≤ content_region.width//2` (runtime), no right-edge clip, non-overlapping. TC GREEN — per-pane `overflow_y=="auto"`, panel grid, `#patch_doc_controls` grid-size 3.
- AT-033c (80+120) GREEN — reparent-safety: `add_entry`→row_count grows, `run_checks`→`Checks:` log line, buttons present (action routing survives).
- **Counterfactual RED (QC-2):** revert grid → vertical stack → panes share `region.x==7` → `len({region.x})==1≠2` → RED. Restored → re-green.
- Full non-slow: **985 → 990 collected (+5)**; 958 passed / 0 failed. `test_tui_patch_editor_v2.py` 26/26 green (ids + `> Static` intact). ruff clean. **Frozen-engine diff 0** (vs origin/main 13c06c4).

## 5. Independent review + fold
- **code-reviewer: APPROVE-WITH-NITS.** Reparent provably complete (id-set diff: 39 `patch_*` ids preserved + 4 panes, none dropped/reordered); `> Static` survives; button-grid genuine; 2×2 proof sound (rejects L-shape, runtime budget); AT-033c genuine routing. 0 HIGH/MED.
- **F1 LOW FOLDED (correctness-of-claim):** the AT-033a docstring + a styles.tcss comment overclaimed that AT-033a's `region.right ≤ host` proves the button-grid no-clip — it proves the PANE stays in host; the button-grid is locked by the TC (`grid_size_columns==3`). A within-pane clip would be masked by `overflow-x:hidden`. Reworded both to attribute the guarantee correctly (5 tests + ruff re-green; docstring/comment only).
- **F2 (LOW, DEFERRED→BACKLOG):** the save-back-SHOWN span (`column-span:2`, no pane squeeze) isn't asserted (row hidden by default; v2 suite checks visibility only). Structurally sound via `1fr 1fr auto` (pane heights independent of the auto row). Optional test logged.

## 6. Risks
- R1 (button-grid) resolved by the TC + AT geometry together. R2 (save-back span) = F2 LOW, deferred. Snapshot cell reconciliation = Inc2.

## 7. Pending / next
- **Increment 2 (HLR-034 / US-031):** geometry snapshot lock — reconcile the `patch-comfortable-120x30` xfail + add an 80×24 patch cell; CI-only baseline regen (xfail-until-CI). The local geometry AT (this increment) is the behavioral verdict.
