# PLAN — batch-27 · Interactive Memory Map minimap

**BLUF:** Replace the read-only monochrome Memory Map text list with an
**interactive color-coded spatial minimap**: a clickable coverage grid (left),
a per-cell detail pane (right) surfacing the covering region + validation issues
+ a Hex-View jump, and a coverage stats strip (bottom). TUI-side only; no
engine-frozen module touched. Prototyped and operator-approved (Variant B v2).

---

## Where we are
- **Phase:** 6 COMPLETE → **`awaiting-sync`** (batch functionally done; operator merge + regen + sync pending)
- **Route:** full `/dev-flow` (operator-directed)
- **Batch id:** `2026-07-06-batch-27`
- **Gate history:** P0 ✅ · P1 ✅ (R-TUI-041, 3 HLR / 11 LLR) · P2 ✅ (1 blocker B-1 markup-injection + 4 majors → iterate-to-refine → CLOSED) · P3 ✅ (Inc1 US-035, Inc2 US-036 +arrow-nav follow-on, Inc3 US-037; each code-reviewed 0 HIGH) · P4 ✅ (14 TC + 11 AT, no blocker) · P5 ✅ (meta-root-cause: controlled-data cross-tech prototype; C-16+C-17 encoded) · P6 ✅ (4 docs).
- **Result:** ledger 1037→1058, 0 engine-frozen diffs, security blocker caught pre-code + fixed, arrow-nav gap caught by hardened AT.
- **Operator TODO:** commit → PR → rebase onto `4452f31` → merge → canonical-CI baseline regen (retire 2 map xfails) → `/dev-flow-sync` (+ index batch-26/27 in MEMORY.md).

## Objective
Turn the Memory Map screen (`MemoryMapPanel`, `s19_app/tui/screens_directionb.py`)
from a `markup=False` per-range text list into an interactive minimap that lets a
firmware engineer locate coverage/validity problems at a glance and jump to them.

## Base currency (RC-1) — PASS
- `git fetch origin` @ 2026-07-06.
- HEAD = merge-base(HEAD, origin/main) = `origin/main` tip = **`6341fd7`** (batch-25 close).
- Clean tree, no rebase/new-cut needed.
- Verified `origin/main` tip recorded here BEFORE derivation.

## Already-shipped check (Phase-0 RC-1 second half)
- `R-TUI-026` (origin/main) covers only the **read-only** Memory Map scaffold
  ("rendering firmware coverage … without computing new coverage data").
- The interactive minimap (clickable cells, detail pane, stats) is **net-new
  behavior** → NOT `SATISFIED-EXTERNALLY`. New requirement **R-TUI-041**
  supersedes/extends R-TUI-026. (Highest existing id = R-TUI-040.)

## Stories (intake — Definition of Ready)
| id | title | INVEST | class |
|----|-------|--------|-------|
| US-035 | Color-coded spatial minimap grid (replaces the text list) | ✓ | READY* |
| US-036 | Cell selection → detail pane (region + issues + Open-in-Hex) | ✓ | READY* |
| US-037 | Coverage stats strip | ✓ | READY* |

`*` READY pending operator confirmation of the 3 design decisions below (gate).

## Open design decisions (resolve at Phase-0 / Phase-1 gate)
1. **Cell size** — fixed 2 KiB vs **auto-scale to fit the pane** for large images.
   → *Recommend auto-scale*, show "≈ N KiB/cell" in the header. (US-035)
2. **Detail-pane placement at <120 cols** — fixed right column vs **reflow to a
   bottom region** in the narrow regime. → *Recommend narrow-regime reflow*;
   **C-13 geometry-budget check required** (Workspace 3-pane taught us fixed side
   panes overflow at 80). (US-036)
3. **Issue→cell anchoring** — issues whose address is inside the clicked cell vs
   all issues for the covering region. → *Recommend cell-scoped primary list +
   a region-issue count* ("3 issues in region"). (US-036)

## Roadmap / increment plan (provisional — firms at Phase 3)
- **Inc 1:** `MemoryMapPanel` grid model + colored render (US-035) — panel + CSS.
- **Inc 2:** cell selection + detail pane + Open-in-Hex wiring (US-036) — panel + `app.py`.
- **Inc 3:** stats strip (US-037) + narrow-regime reflow + snapshot cell/xfail.
- (Increment boundaries provisional; ≤5 files each.)

## Risks / watch-items
- **R1 — snapshot baselines.** Flipping `markup=False`→colored markup changes
  several of the 28 SVG baselines. Local regen FORBIDDEN (`snapshot-regen-env`
  memory); textual pinned `8.2.8` in `[dev]`. Plan: add the map snapshot cell(s)
  as **xfail-until-baseline**, regen in canonical CI env post-merge (batch-25 pattern).
- **R2 — parallel batch-26 merge.** Keep the diff surgical: `screens_directionb.py`,
  `app.py`, `styles.tcss`, `REQUIREMENTS.md`, `tests/`. Expect conflict on
  `styles.tcss`/`app.py`/baselines at rebase; resolve at merge, not now.
- **R3 — C-13 geometry.** The right detail pane is a NEW fixed sibling in the map
  screen; must compute the 80-col budget before committing a fixed width (decision 2).
- **R4 — thread split.** Panel must stay render-only (driven by
  `update_memory_map` on the UI thread); the issues↔cell JOIN reads the
  already-computed `ValidationReport`, no new parse/coverage analysis.

## Conventions honored
- Engine-frozen set untouched (core/hexfile/range_index/validation/a2l/mac/color_policy).
- Colors via `color_policy` sev-* palette (single source of truth); cyan accent for selection.
- Docstring section order; type hints; ≤5 files/increment; dual traceability (AT + TC).

## Out-of-scope (carries)
- Variants A / C (linear band, band+table) — not chosen.
- Bookmarks screen (separate P1 gap — future batch).
- Any change to how `ranges` / `range_validity` / issues are COMPUTED (engine).

## Test ledger
- Base test count: TBD (measure at Phase 3 entry). `post = base − D + A`.

## Decision log (human mirror of state.json)
- 2026-07-06 — batch-27 opened; RC-1 PASS @ 6341fd7; batch-26 collision → took 27.
- 2026-07-06 — already-shipped: R-TUI-026 read-only only → new R-TUI-041.
