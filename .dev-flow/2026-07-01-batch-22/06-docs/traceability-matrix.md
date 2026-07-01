# Traceability Matrix — s19_app — Batch 2026-07-01-batch-22

> Two chains (Two-layer validation rule) — a story is complete only when BOTH exist:
> - **Functional (white-box):** User Story → HLR → LLR → `TC-NNN` → File:line.
> - **Behavioral (black-box):** User Story → `AT-NNN` → observed outcome through the shipped surface.
>
> **Batch scope:** feature #8 (patch-editor overhaul) **slice 2** — the 4-pane 2×2 split (US-030) and its geometry snapshot lock (US-031). Continues batch-21 slice 1 (change-file management + Checks clarity). All node names below are the real on-disk pytest node ids. Frozen-engine diff = 0.

---

## 1. Master table — functional chain (white-box)

| US | HLR | LLR | TC | File:line | Status | Notes |
|----|-----|-----|-----|-----------|--------|-------|
| US-030 | HLR-033 | LLR-033.1 (2×2 grid on `#patch_editor_panel`) | `tests/test_tui_patch_layout.py::test_tc_pane_styles_and_grid` | `s19_app/tui/styles.tcss:560` (`#patch_editor_panel { layout: grid; grid-size: 2 3; grid-rows: 1fr 1fr auto }`) | pass | Grid geometry white-box lock |
| US-030 | HLR-033 | LLR-033.2 (four `#patch_pane_*` reparent, inner ids preserved) | `tests/test_tui_patch_layout.py::test_tc_pane_styles_and_grid` | `s19_app/tui/screens_directionb.py:627` (entries) / `:663` (changefile) / `:706` (checks) / `:717` (variant) | pass | Every `patch_*` id + action queryable post-reparent |
| US-030 | HLR-033 | LLR-033.3 (per-pane independent vertical scroll) | `tests/test_tui_patch_layout.py::test_tc_pane_styles_and_grid` | `s19_app/tui/styles.tcss:570` (`#patch_pane_* { overflow-y: auto; overflow-x: hidden }`) | pass | |
| US-030 | HLR-033 | LLR-033.3b (Change-file button row → explicit 3-col grid, flows to 2 rows) | `tests/test_tui_patch_layout.py::test_tc_pane_styles_and_grid` | `s19_app/tui/styles.tcss:690` (`#patch_doc_controls { layout: grid; grid-size: 3 }`) | pass | `Horizontal` does not wrap → would clip; `grid_size_columns == 3` asserted |
| US-030 | HLR-033 | LLR-033.4 (save-back row = `column-span: 2` grid child in auto 3rd row) | `tests/test_tui_patch_layout.py::test_tc_pane_styles_and_grid` | `s19_app/tui/screens_directionb.py:734` (span child) + `s19_app/tui/styles.tcss:582` (`#patch_saveback_row { column-span: 2 }`) | pass | Zero-height while hidden — panes not squeezed |
| US-031 | HLR-034 | LLR-034.1 (2×2 SVG snapshot cell @ 80×24) | `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-80x24]` | `tests/test_tui_snapshot.py:384` (`_SCAFFOLD_CELLS`, `xfail(strict=False)`) | CI-locked | Baseline regenerates in CI env only — SKIP-local / xfail-CI until baseline lands |
| US-031 | HLR-034 | LLR-034.2 (2×2 SVG snapshot cell @ 120×30) | `tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot[patch-comfortable-120x30]` | `tests/test_tui_snapshot.py:384` (`_SCAFFOLD_CELLS`, `xfail(strict=False)`) | CI-locked | Same regen dependency; matrix 27→28 |

## 1b. Behavioral chain (black-box)

> Per user story: the acceptance test that observes the outcome through the shipped surface. A story with a complete functional chain but no behavioral row is INCOMPLETE.

| US | Acceptance test (`AT-NNN`) | Shipped surface | Observed outcome / deliverable | Status |
|----|----------------------------|-----------------|--------------------------------|--------|
| US-030 | `tests/test_tui_patch_layout.py::test_at_033a_two_by_two_at_80_floor` (AT-033a) | Patch Editor screen driven through Pilot @ **80×24** | All four `#patch_pane_*` regions laid out 2×2 (two columns × two `1fr` rows), each region `.right <= host` — no pane off-screen at the 80-col floor | pass |
| US-030 | `tests/test_tui_patch_layout.py::test_at_033b_two_by_two_at_120` (AT-033b) | Patch Editor screen driven through Pilot @ **120×30** | Same 2×2 geometry holds at the wide breakpoint; all four panes visible together | pass |
| US-030 | `tests/test_tui_patch_layout.py::test_at_033c_reparent_safety_at_80` + `::test_at_033c_reparent_safety_at_120` (AT-033c) | Patch Editor screen driven through Pilot @ 80×24 **and** 120×30 | Every pre-existing `patch_*` inner widget id resolves after the reparent into the four panes — no id lost / renamed / orphaned | pass |
| US-031 | *(no separate AT)* — behaviorally covered by US-030 AT-033a/b/c | — | The 2×2 layout is **behaviorally proven** through the shipped surface by US-030's AT set. US-031 only locks a pixel-baseline (SVG); no independent behavioral claim. | covered via US-030 |

---

## 2. Coverage summary

| Metric | Value |
|--------|-------|
| Total user stories | 2 (US-030, US-031) |
| Covered user stories | 2 (100%) |
| Total HLR | 2 (HLR-033, HLR-034) |
| Implemented HLR | 2 (100%) |
| Total LLR | 8 (033.1, 033.2, 033.3, 033.3b, 033.4, 034.1, 034.2) — 6 net-new statement rows + 2 snapshot LLR (ledger 985→991, +6) |
| Implemented LLR | 8 (100%) |
| Test cases (functional TC) | 1 (`test_tc_pane_styles_and_grid`) |
| Acceptance tests (behavioral AT) | 4 nodes across 3 AT ids (AT-033a, AT-033b, AT-033c×2) |
| Snapshot cells (US-031) | 2 (AT-034a, AT-034b) |
| PASS (functional TC + behavioral AT) | 5 nodes (TC-033, AT-033a, AT-033b, AT-033c×2) |
| CI-locked (snapshot) | 2 nodes (AT-034a, AT-034b) — `xfail(strict=False)` until CI baseline |
| fail | 0 |
| pending | 0 |

---

## 3. Detected gaps

> No functional or behavioral gaps. The two CI-locked snapshot nodes are **not** a coverage gap: the 2×2 layout is behaviorally proven by US-030's AT-033a/b/c; US-031 is a pixel-baseline lock whose baseline can only be regenerated in the canonical CI env (local regen drifts unrelated Textual baselines — see MEMORY `reference_snapshot_regen_env`), so both cells ride `xfail(strict=False)` until that baseline lands.

| ID | Type | Description | Proposed action |
|----|------|-------------|-----------------|
| — | — | (none) | — |

**CI-baseline follow-on (tracked, not a gap):** regenerate the two `patch-comfortable-*` SVG baselines in the canonical CI env; once green, flip AT-034a/AT-034b from `xfail` to asserting and promote R-PATCH-2X2-SNAPSHOT-001 from `CI-locked` to `Automated`.

---

## 4. Changes from previous batch

| Type | Item | Detail |
|------|------|--------|
| new | HLR-033 / US-030 | Patch Editor reorganized from a ~12-group vertical stack into a 2×2 grid of four area-panes |
| new | HLR-034 / US-031 | Two SVG geometry-lock snapshot cells added; snapshot matrix 27→28 |
| new | `R-PATCH-2X2-LAYOUT-001`, `R-PATCH-2X2-SNAPSHOT-001` | Proposed REQUIREMENTS.md §28 (see docs packet) |
| carried | batch-21 slice 1 | US-026/027/029 (change-file dropdown, `patches/` folder, Checks-clarity Label) unchanged; this slice sits above them |
| deferred (still BACKLOG) | US-028 | Inline variant dropdown — not in this slice |

---

## 5. Quick bidirectional mapping

### 5.1 By user story
- **US-030** → HLR-033 → LLR-033.1, 033.2, 033.3, 033.3b, 033.4 → `test_tc_pane_styles_and_grid` (TC) + AT-033a / AT-033b / AT-033c (behavioral)
- **US-031** → HLR-034 → LLR-034.1, 034.2 → `test_tc016s_density_layout_snapshot[patch-comfortable-80x24 | 120x30]` (AT-034a / AT-034b, CI-locked)

### 5.2 By code file
- `s19_app/tui/styles.tcss` → LLR-033.1 (`#patch_editor_panel` grid @:560), LLR-033.3 (`#patch_pane_*` overflow @:570), LLR-033.3b (`#patch_doc_controls` grid @:690), LLR-033.4 (`#patch_saveback_row` span @:582) → TC-033
- `s19_app/tui/screens_directionb.py` → LLR-033.2 (four-pane reparent @:627/:663/:706/:717), LLR-033.4 (span child @:734) → TC-033 + AT-033c
- `tests/test_tui_snapshot.py` → LLR-034.1, 034.2 (`_SCAFFOLD_CELLS` @:384, `_SIZES` @:99, `_SCAFFOLD_SCREENS` @:109) → AT-034a / AT-034b

### 5.3 Boundary / safety nodes
- **AT-033a** is the **80-column floor boundary gate** — the tightest supported width, where a mis-sized pane would spill off-screen first (`region.right <= host`).
- **AT-033c** is the **reparent-safety node** — guards that the wholesale sub-tree move into four panes lost no inner `patch_*` id or its action wiring.

---

## 6. Batch sign-off

| Field | Value |
|-------|-------|
| Batch ID | 2026-07-01-batch-22 |
| Closing date | 2026-07-01 |
| Total iterations (sum of phases) | `<to be filled at close>` |
| Validation passed | yes (functional TC + behavioral AT PASS; snapshot cells CI-locked by design, not failing) |
| Synced to Obsidian | `<pending post-merge>` |
