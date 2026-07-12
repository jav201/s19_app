# Increment 003 — US-058 Patch Editor: readable paste box + uncluttered controls

Batch 2026-07-11-batch-36 · Increment 3 (final) · Scope = **US-058 only** · **compose + CSS only**
(no handler / binding / id changes). LLRs: 058.1 (mechanism + MEASURED N), 058.2 (reparent +
sibling-disjoint), 058.3 (id/wiring census), 058.4 (snapshot xfail).

---

## 1. What changed

The change-set paste group (`#patch_paste_row`: its label, `#patch_paste_text`, and the
`#patch_paste_parse_button` row) was **reparented OUT of the crowded top-right
`#patch_pane_changefile` grid cell** — where it stacked below the change-file + patch-script +
checks groups and was pushed **fully below the fold** (0 in-viewport editor lines at scroll 0) —
**into its own dedicated full-width panel cell** in a **weighted** grid row.

- `PatchEditorPanel.compose` now yields `#patch_paste_row` as a **top-level panel grid child**
  (after the four `#patch_pane_*` panes, before the save-back row) instead of nesting it inside
  `#patch_pane_changefile`. `#patch_pane_changefile` now wraps only `#patch_doc_file_row`.
- The panel grid became `grid-size: 2 4` with **`grid-rows: 1fr 2fr 2fr auto`** (was
  `grid-size: 2 3` / `grid-rows: 1fr 1fr auto`). Rung-1 realization: the paste cell spans both
  columns (`column-span: 2`) and scrolls per-pane (`overflow-y: auto`).
- **WEIGHTED, not equal** (LLR-058.1): the MEASURED 5-row-@80x24 budget cannot give the paste
  cell a usable slice under an equal split, and an equal split ALSO starved the checks/variant
  middle row (see §5 deviation). `1fr 2fr 2fr` gives the paste row AND the checks/variant row
  each 2 of the 5 rows @80x24; the entries/change-file top row takes the remaining 1 and scrolls.

No `on_button_pressed` branch, handler, or key binding touched. `#patch_paste_text { height: 8 }`
retained. The batch-35 US-057 two-section labels (`#patch_script_section_label` /
`#patch_checks_section_label`) and the button-grid `#patch_doc_controls` (`grid-size: 3`, ≥ 8-col
cells so `"Validate"` never clips) are untouched.

## 2. Files modified (5 — within cap)

| File | Change |
|---|---|
| `s19_app/tui/screens_directionb.py` | `compose`: reparent `#patch_paste_row` to a top-level grid cell; docstring updated to `grid-size: 2 4` / `grid-rows: 1fr 2fr 2fr auto`. |
| `s19_app/tui/styles.tcss` | `#patch_editor_panel` → `grid-size: 2 4` + `grid-rows: 1fr 2fr 2fr auto`; new `#patch_paste_row` rule (`column-span: 2; height: 100%; overflow-y: auto; overflow-x: hidden`). |
| `tests/test_tui_patch_layout.py` | +AT-058a (`test_at058a_paste_editor_in_viewport_and_separated`, one node, both widths); `+TextArea` import; `_PASTE_INVIEW_MIN` pins. |
| `tests/test_tui_patch_editor_v2.py` | +AT-058b (`test_at058b_id_census_and_wiring_survive_reparent`, 15-id census + AT-032b wiring re-assert). |
| `tests/test_tui_snapshot.py` | +`_batch36_drift_marks` (xfail both patch cells) wired into `_SCAFFOLD_CELLS`; +TC-321 (`test_tc321_batch36_patch_xfail_set`). |

The Inc-1 (legend) + Inc-2 (fixtures) files already in the working tree were NOT touched.

## 3. How to test

```bash
# GREEN gate (one complete run — C-19)
pytest tests/test_tui_patch_layout.py tests/test_tui_patch_editor_v2.py tests/test_tui_patch_variant.py -q
# Snapshot: confirm the 2 patch cells xfail (not fail) + TC-321
pytest tests/test_tui_snapshot.py -q -k patch
pytest tests/test_tui_snapshot.py -q          # no OTHER cell regresses
# Behavioral regression over the reparent (wiring survives)
pytest tests/test_variant_execution.py tests/test_before_after_report.py tests/test_tui_memory_patch.py tests/test_tui_report_filter_surface.py -q
# Engine-frozen guard (0 diffs — no frozen file touched)
pytest tests/test_engine_unchanged.py tests/test_tui_directionb.py::test_tc031_engine_modules_have_no_diff_vs_main -q
```

## 4. Test results

### MEASURED geometry — BEFORE (RED) vs AFTER (Pilot at scroll_y == 0)

| Width | State | `#patch_paste_text.region (x,y,w,h)` | paste pane content-region | in-viewport editor lines |
|---|---|---|---|---|
| 80x24 | BEFORE | (42, **38**, 33, 8) | `#patch_pane_changefile` = [8,10) | **0** (below fold) |
| 80x24 | AFTER | (7, **12**, 68, 8) | `#patch_paste_row` = [11,13) | **1** |
| 120x30 | BEFORE | (71, **36**, 44, 8) | `#patch_pane_changefile` = [8,13) | **0** (below fold) |
| 120x30 | AFTER | (25, **15**, 90, 8) | `#patch_paste_row` = [14,19) | **4** |

Panel content height (F-01 confirmed): 5 rows @80x24 / 11 @120x30. AFTER pane split @80x24 =
entries/change-file row 1 row, checks/variant row 2 rows, paste row 2 rows; @120x30 = 2 / 4 / 5.

### Pinned N_w (from the POST-fix capture — LLR-058.1)

- **N_80 = 1** (spec provisional 1) — placement predicate `11 ≤ 12` and `12 + 1 ≤ 13` ✓.
- **N_120 = 4** (spec provisional 3; MEASURED **4** > provisional) — `14 ≤ 15` and `15 + 4 ≤ 19` ✓.
- Both strictly > today's **0** in-viewport lines. First paste line inside the visible
  content-region at both widths.

### RED → GREEN evidence

- **RED (C-20, pre-change source):** reverted `screens_directionb.py` + `styles.tcss` to HEAD
  (kept the AT), ran `test_at058a_...` → **FAILED**: `#patch_paste_row` IS a descendant of
  `#patch_pane_changefile` (non-descendant guard trips) and the placement predicate would also
  fail (paste.y=38 vs content `[8,10)` → 0 lines). `1 failed`. Source then restored from backup.
  (No `git stash` — a direct file-level revert/restore, C-20.)
- **GREEN:**
  - `pytest test_tui_patch_layout.py test_tui_patch_editor_v2.py test_tui_patch_variant.py -q`
    → **56 passed**, exit 0.
  - `pytest test_tui_snapshot.py -q -k patch` → **1 passed, 2 xfailed**, exit 0
    (`patch-comfortable-80x24` + `patch-comfortable-120x30` xfail; TC-321 pass).
  - `pytest test_tui_snapshot.py -q` → **33 passed, 2 xfailed**, exit 0 (no other cell drifts).
  - `pytest test_variant_execution.py test_before_after_report.py test_tui_memory_patch.py test_tui_report_filter_surface.py -q`
    → **45 passed**, exit 0 (wiring survives the reparent).
  - Engine-frozen guards: `test_engine_unchanged.py` (1 passed) +
    `test_tc031_engine_modules_have_no_diff_vs_main` / `...no_name_only_diff...` (2 passed) —
    **0 diffs** (no frozen file touched).

### Snapshot-drift disposition (C-22 — per cell)

| Cell | Drifts? | Why | Mark |
|---|---|---|---|
| `patch-comfortable-80x24` | Yes | Paste box relocates from inside the TR pane to a full-width row below the four panes; the panes lose a row. | `xfail(strict=False)` |
| `patch-comfortable-120x30` | Yes | Same reparent; paste row now 5 rows, panes reflow. | `xfail(strict=False)` |

Local SVG regen FORBIDDEN (`reference_snapshot_regen_env`); the canonical CI regen retires the
marks post-merge. `strict=False` — if either cell somehow did not drift below the fold it still
passes; both DID drift here (2 xfailed). This SUPERSEDES the batch-35 parked patch mark (already
retired at `7df60dd` via PR #65; the current tree had 0 parked marks before this increment).

### TC-319 SURVIVES

`test_tc319_regroup_section_structure_census` passed unchanged: it queries
`#patch_doc_file_row.children` (which never contained `#patch_paste_row` — always a sibling) and
the 15-id `app.query` census (global, invariant under a reparent). No rung reorders
`#patch_doc_file_row`'s own children, so no docstring update was owed. AT-033a/b (2x2 grid) also
survive — the four `#patch_pane_*` keep 2 distinct region.x and 2 distinct region.y within budget.

## 5. Risks

- **Height-starved shell (F-01 residual, accepted).** @80x24 the paste editor shows **1**
  in-viewport line (first line visible — a real improvement over the below-fold 0); full
  multi-line readability is a 120x30 affordance (**4** lines). This is the LLR-058.1 "first
  option" (accept a low N_80, no scope expansion) — no focus-to-expand / sub-view was added.
- **Top-row compression.** The entries/change-file top row is 1 row @80x24 (was 2); both panes
  scroll (`overflow-y: auto`), and AT-033a/b + the behavioral suites confirm no clip/wiring loss.
- **Snapshot marks are provisional** until the canonical CI regen recommits the 2 baselines.

## 6. Pending items

- Canonical-CI SVG regen (post-merge) to recommit `patch-comfortable-{80x24,120x30}` baselines and
  drop the `_batch36_drift_marks` xfail (follow-up, exactly as batch-25/33 did).
- REQUIREMENTS.md ledger row **R-TUI-046** (US-058) — Phase-6 docs step, not this increment.

## 7. Suggested next task

Phase-4 validation gate for batch-36 (fuse Inc-1/Inc-2/Inc-3), then Phase-6 docs
(REQUIREMENTS.md R-TUI-046/047/048 + `.dev-flow/BACKLOG.md` refresh).

---

### Evidence checklist

- [x] Tests/type checks/lint pass — 56 + 45 + snapshot green; ruff `All checks passed!` on the 4
  changed `.py`; `--collect-only` = **1370** (base 1367 − D 0 + A 3: AT-058a, AT-058b, TC-321).
- [x] No secrets in code or output.
- [x] No destructive commands — file-level `git checkout --`/restore for the RED capture only
  (no `git stash`, no `rm -rf`, no force).
- [x] File count within cap — **5** files (`screens_directionb.py`, `styles.tcss`,
  `test_tui_patch_layout.py`, `test_tui_patch_editor_v2.py`, `test_tui_snapshot.py`).
- [x] Review packet attached (this file).

### C-18 note

AT-058a is **one on-disk node** (`test_at058a_paste_editor_in_viewport_and_separated`) that loops
over both widths internally; AT-058b is one node; TC-321 is one node. No AT is split across nodes.

### Deviation from the spec (surfaced — C-20/12 honesty)

1. **`grid-rows: 1fr 2fr 2fr auto` (not `1fr 1fr 2fr auto`).** The spec's illustrative rung-1
   used `1fr 1fr 2fr auto`; MEASURED, that gave the paste cell 3 rows @80x24 (N_80=2) but starved
   the **checks/variant** middle row to 1 row, which pushed the variant `Select` below the fold
   and broke **TC-035.2** (`test_tc_035_2_variant_group_above_execute_row`). Rebalancing to
   `1fr 2fr 2fr auto` restores the variant Select's visibility (middle row = 2 rows) while keeping
   the paste editor's first line in-viewport (paste row = 2 rows). Cost: **N_80 = 1** instead of 2
   (still > 0 and = the spec provisional). This is still **rung-1** (dedicated reparented paste
   cell, weighted rows, no scope expansion) — only the weight vector changed.
2. **Sibling-disjointness guard target.** The spec's AT-058a names `#patch_doc_file_row` for the
   rectangle-disjointness guard, but its raw `.region` **overflows its scroll pane** (h=29 vs the
   1-2 visible rows @80x24, F-01), so raw-region disjointness with it is unsatisfiable. The AT
   instead asserts (a) `#patch_doc_file_row` is contained in `#patch_pane_changefile` (child ⊂
   parent, per LLR-058.2), and (b) the paste cell is disjoint from the grid-sibling
   `#patch_pane_changefile` (the pane that clips the cluster = the on-screen cluster rectangle).
   This is the physically-correct expression of "paste cell separated from the change-file
   cluster at the sibling level"; the C-10 readability discriminator remains the content-region
   placement predicate, unaffected.

### Per-LLR coverage

| LLR | On-disk test(s) | Result |
|---|---|---|
| 058.1 (mechanism + MEASURED N) | `test_at058a_paste_editor_in_viewport_and_separated` (placement + N_80=1/N_120=4) | GREEN |
| 058.2 (reparent + sibling-disjoint, no clip) | `test_at058a_...` (non-descendant + containment + disjoint + no-clip) | GREEN |
| 058.3 (id + wiring census) | `test_at058b_id_census_and_wiring_survive_reparent` (15 ids + AT-032a token + run_checks route) + TC-319 survives | GREEN |
| 058.4 (snapshot xfail) | `test_tc321_batch36_patch_xfail_set` + the 2 xfailed patch cells | GREEN (1 pass, 2 xfail) |
