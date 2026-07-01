# Functionality — s19_app — Batch 2026-07-01-batch-22

> Phase 6 artifact. Owner: `docs-writer`. Audience: technical stakeholder (TUI maintainers + reviewers).
> Feature #8 (patch-editor overhaul) **slice 2**: the 4-pane 2×2 split.

## 🔑 At a glance (read first)

- **What this batch added:** the Patch Editor screen now shows its four working areas — **Entries · Change-file · Checks · Variant** — as a **2×2 grid** where all four are visible at once, instead of one long vertical scroll you had to page through to see everything.
- **Capabilities:**
  - Four area-panes laid out top-left / top-right / bottom-left / bottom-right, each **scrolling independently**.
  - The Change-file button row (Load · Validate · Apply · Save · Run checks) **flows onto two rows** inside its pane instead of clipping off the edge.
  - The save-back prompt still spans the **full width** below the grid when shown.
  - A geometry snapshot lock pins the 2×2 at the two supported terminal sizes (80×24, 120×30).
- **How to use it:** launch `s19tui`, open the **Patch Editor** rail item (`6`). No new keys, buttons, or actions — every existing `patch_*` control is exactly where it was, just relocated into its pane. Nothing about *what* the controls do changed.

> Enough to know what shipped and how to reach it. Detail below for how it works.

---

## Detail (reference)

### How it works (flow)

Before this slice, `PatchEditorPanel.compose` yielded ~12 sibling groups (section title, entries table, entry inputs, the change-file row, the paste row, the issues/checks area, the variant row, the save-back row …) straight into a single scrolling `ScrollableContainer`. To read the Checks output or the variant controls you scrolled the whole panel down and lost sight of the entries.

This slice **reparents** those groups into **four `Container` area-panes** and lays the panel out as a CSS grid:

- **`#patch_pane_entries`** (top-left) — section title, the entries `DataTable`, the empty-state line, and the Address / String value / Bytes / Add·Edit·Remove input block.
- **`#patch_pane_changefile`** (top-right) — the Change-file `Select` dropdown + path input + the Load·Validate·Apply·Save·Run-checks control row + the Checks-clarity Label (batch-21), and the paste-changeset row.
- **`#patch_pane_checks`** (bottom-left) — the issue count, the issues `Static`, the Checks status line, and the checks results container.
- **`#patch_pane_variant`** (bottom-right) — the Execute-over-variants row (scope button + execute button).

The panel itself becomes `layout: grid; grid-size: 2 3` (two columns × three rows) with `grid-rows: 1fr 1fr auto`. The two `1fr` rows host the four panes; the **`auto` third row** is the declared home for the hidden **save-back prompt**, which is yielded as a direct grid child with `column-span: 2` so it spans both columns full-width when shown and stays zero-height while hidden — so the four panes are never squeezed by a control that is not on screen.

Each pane carries `overflow-y: auto; overflow-x: hidden`, so **vertical scroll moved from the panel to the individual pane** — a long entries table scrolls within the top-left pane while the Checks pane stays put.

**Key reparent rule:** each area's pre-existing widget sub-tree is moved **wholesale** — no inner id is renamed or reordered. Every `patch_*` widget id and its action wiring stay queryable. That property is what AT-033c (reparent-safety) verifies at both terminal sizes.

### The Change-file button-row fix (why a grid, not a `Horizontal`)

The Change-file pane is the tightest of the four (~35 columns at an 80-col terminal). Textual's `Horizontal` container **does not wrap** — it lays its five buttons (Load · Validate · Apply · Save · Run checks) on one line and **clips** whatever overflows the pane. So `#patch_doc_controls` was changed to an explicit **3-column button grid** (`layout: grid; grid-size: 3`), which flows the five buttons deterministically onto two rows within the pane budget. This is version-stable and CSS-only. The white-box TC asserts `grid_size_columns == 3` — because AT-033a's `region.right <= host` check only proves the *containing pane* stays on-screen; a within-pane clip would be masked by the pane's own `overflow-x: hidden`, so the grid-size assertion is the belt-and-suspenders guard.

### Measured-geometry rationale (why 2×2 is safe)

The Phase-0 spike measured the panel's content width on the host: **70 columns at 80-wide** and **92 columns at 120-wide**. Split two columns → ~35 columns per pane at 80. That clears the C-13 geometry budget (available − fixed siblings ≥ required footprint), which is why the 2×2 is safe at the 80-column floor and did not need a fallback-to-stacked rung. AT-033a is the **80-column floor boundary gate** — the tightest supported width, where any mis-sized pane would spill off-screen first.

### The snapshot lock (US-031) and its CI follow-on

US-031 adds two SVG snapshot cells that pin the 2×2 pixel layout at 80×24 and 120×30 (snapshot matrix 27→28). SVG baselines can only be regenerated in the **canonical CI environment** — regenerating locally drifts unrelated Textual baselines and breaks CI (project rule). So both patch cells ride `xfail(strict=False)` until the CI baseline lands: they neither fail the suite nor claim a false pass. **The 2×2 is not proven by these cells — it is behaviorally proven by US-030's AT-033a/b/c.** US-031 only locks the pixels once a baseline exists.

**Follow-on:** regenerate the two `patch-comfortable-*` baselines in CI, confirm green, then flip both cells from `xfail` to asserting and promote the snapshot requirement from `CI-locked` to `Automated`.

### Components / modules touched

| Module | Role in this batch |
|--------|--------------------|
| `s19_app/tui/screens_directionb.py` | `PatchEditorPanel.compose` reparented into four `#patch_pane_*` containers (`:627` entries / `:663` changefile / `:706` checks / `:717` variant) + the save-back span child (`:734`). Inner ids untouched. |
| `s19_app/tui/styles.tcss` | `#patch_editor_panel` grid (`:560`), `#patch_pane_*` per-pane overflow (`:570`), `#patch_saveback_row { column-span: 2 }` (`:582`), `#patch_doc_controls { grid-size: 3 }` (`:690`). |
| `tests/test_tui_patch_layout.py` | Behavioral AT-033a/b/c (Pilot-driven at 80×24 + 120×30) + white-box TC-033 (`test_tc_pane_styles_and_grid`). |
| `tests/test_tui_snapshot.py` | US-031 snapshot cells added to `_SCAFFOLD_CELLS` (`:384`), `patch` in `_SCAFFOLD_SCREENS` (`:109`), sizes from `_SIZES` (`:99`) — both `xfail(strict=False)`. |

> **Frozen-engine diff = 0.** No parsing-layer engine module (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py`) was touched — this is a view-layer-only batch.

### Usage / examples

```bash
# Launch the TUI, then press 6 (Patch Editor rail item)
s19tui

# Or preload firmware and open the editor
s19tui --load examples/case_00_public/prg.s19
```

Run the batch's tests:

```bash
# Behavioral (2×2 geometry, reparent safety) + white-box (grid styles) — all PASS
pytest -q tests/test_tui_patch_layout.py

# The two snapshot cells (SKIP local / xfail-CI until baseline regenerated)
pytest -q "tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24]" \
          "tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]"
```

### Diagrams

- `06-docs/diagrams/batch-22-flows.md` — (a) the 2×2 grid layout (four panes + the full-width save-back span row); (b) the reparent mapping (the ~12 flat compose groups → four panes).

### Evidence checklist — docs-writer

| Item | ✓/✗ | Evidence |
|------|-----|----------|
| Audience & purpose declared at top | ✓ | Header: technical stakeholder, patch-editor 2×2 split |
| Structure follows the functionality template | ✓ | At-a-glance + Detail (flow / modules / usage / diagrams) |
| Code/CLI snippets actually run (or marked untested) | ✓ | `pytest tests/test_tui_patch_layout.py` = PASS per batch facts; snapshot cells marked SKIP/xfail honestly |
| Assumptions listed | ✓ | Measured host 70/92 cols (Phase-0 spike) stated as the basis for 2×2 safety |
| Risks / limitations called out | ✓ | Snapshot cells CI-locked (not a pass); `Horizontal` clip risk documented; follow-on stated |
| Next steps stated | ✓ | CI-baseline regen follow-on for US-031 |
| Diagrams where flow is non-trivial | ✓ | reparent-mapping + 2×2 layout in `diagrams/batch-22-flows.md` |
| No invented APIs / version numbers / metrics | ✓ | All file:line seams verified against final tree; 70/92, 27→28, 985→991 from batch facts |
