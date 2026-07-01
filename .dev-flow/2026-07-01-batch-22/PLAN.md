# PLAN.md — batch-22 (living compendium)

> **#8 patch-editor overhaul — SLICE 2: US-030 (4-pane split) + US-031 (geometry snapshots).**
> The geometry-heavy story deferred from batch-21. **C-13/C-13.1 is the whole batch.** Inline-paste at gates.

## Where we are
- **Phase 6 — Documentation.** `awaiting-gate`. 06-docs (matrix/functionality/diagrams/exec-summary) written; REQUIREMENTS §28 added (US-031 honestly CI-locked); BACKLOG refreshed (#8 slice-2 DONE, US-028 last). Next: operator approval → commit/PR/sync.
- Phase 5 `approved` (control decision: don't-encode/watch). Phase 4 `approved` (PASS). Phase 3 COMPLETE (985→991 +6). Phases 0-2 approved.
- Phase 2 `approved` (0 blockers; R1 Horizontal-no-wrap folded). Phase 1/0 `approved`.
- **Git note:** origin/main advanced to 13c06c4 via the concurrent hooks task (PR #33, benign, batch-22 targets untouched); branch ff'd current; pre-commit artifact hook now live.

## Test ledger (collected non-slow)
- Base (origin/main 13c06c4): batch-21 closed 985.
- **Inc1: 985 → 990 (+5)** — AT-033a/b/c + TC. 0 fail. Frozen 0.
- **Inc2: 990 → 991 (+1)** — patch-80x24 snapshot cell (skips locally, xfail-in-CI). 958 passed / 0 fail. Frozen 0.
- **Phase-3 total: 985 → 991 (+6).** 0 fail throughout.
- Carries: F2 (save-back shown-span test) → BACKLOG optional; pre-existing F401 (`Optional`) in test_tui_snapshot.py; CI baseline regen for the patch cells (post-merge).

## Roadmap / increment plan (Phase-1)
- **Inc1 — HLR-033 reparent** (`screens_directionb.py` + `styles.tcss`): wrap 10 flat compose yields into 4 `#patch_pane_*` containers; grid CSS `grid-size 2 2` + per-pane overflow; save-back `column-span:2`; keep `#patch_checks_results > Static` direct. AT-033a/b/c.
- **Inc2 — HLR-034 geometry AT + snapshot** (`test_tui_patch_layout.py` new + `test_tui_snapshot.py`): local geometry AT (gate-blocking); reconcile the existing `xfail` patch snapshot cell + add 80×24; baseline regen CI-only (xfail-until-CI). AT-034a/b.

## Key decisions
- 2×2 grid (not 4-across/nesting); save-back column-span:2; US-031 = geometry AT (local verdict) + snapshot (CI-locked, no fabricated local pass). 2 render-time assumed items → Phase-3 geometry AT confirms.

## SPIKE RESULT (measured 2026-07-01)
- `#patch_editor_panel` content width: **70 @80 · 92 @120** (via Pilot, real app). Batch-21's ~37/~58 estimate assumed a shared workspace body — WRONG; the patch screen is near-full-width minus the rail.
- **2×2 grid** = ~35/~46 per pane → comfortable, budget-clear at 80. **4-across** = ~17 @80 → underflows the 5-button controls row → STRUCK.
- C-13.1 ladder: PRIMARY 2×2 (deficit-free) · rung-2 wrap button row (free, vertical scroll) · rung-3 responsive stack (only if <80 supported).
- 4 areas: entries / change-file / checks / variant (+ hidden saveback overlay).

## Objective
Split `PatchEditorPanel` (currently a single vertical `ScrollableContainer` @`screens_directionb.py:335`, ~10 stacked groups) into a **4-pane layout** so the entries / change-file / checks / variant areas are visible together — WITHOUT clipping/underflow at 80 or 120 cols. US-031 = the geometry snapshot baselines that lock it.

## RC-1 base-currency gate (batch-22 open) — PASS
- `git fetch` → `origin/main` = **74f19ac** (batch-21 PR #34 merged). branch ff'd `590ac30 → 74f19ac` (HEAD == origin/main). Clean.
- Carried (uncommitted → ride batch-22 first commit): batch-21 close snapshot + the BACKLOG UI-focus optional item.

## The central risk — C-13/C-13.1 (this batch exists because of it)
- batch-17 US-018 + batch-18 US-023 both tripped on unmeasured geometry; batch-21 deferred US-030 precisely so it gets its own measured batch.
- **Phase 0 MUST produce:** (a) the measured host content width at 80 AND 120 cols (batch-21's ~37/~58 estimate is UNVERIFIED — verify by running the app under Pilot at both sizes); (b) the 4-pane decomposition (which panes, which widgets each); (c) per-pane budget arithmetic (available − fixed siblings vs required footprint) at the tightest regime (80 cols); (d) a **deficit-matched fallback ladder** (C-13.1) — if 4 horizontal panes underflow at 80, pre-select the rung whose recovery ≥ the deficit (e.g. responsive 2×2 / stacked-below-N-cols / tabbed panes), not the cheapest rung.

## Roadmap (provisional — finalize after spike)
- TBD after measurement. Likely: the split may need a responsive layout (4 panes @120, fewer/stacked @80) rather than a fixed 4-across.

## Key decisions
- Scope = US-030 + US-031 (operator, over US-028/hooks/#12).

## Risks / watch-items
- **Underflow at 80 cols** is the likely finding — a 4-across split into ~37 cols = ~9 cols/pane, unusable. Expect a responsive/stacked fallback (C-13.1).
- **SVG snapshots (US-031):** regenerate ONLY in the canonical CI env (memory: local regen drifts baselines) — the snapshot baselines are the US-031 deliverable but must be created carefully.
- Engine-frozen OFF-LIMITS; the split lives in `screens_directionb.py` + `styles.tcss` (+ maybe app.py for any activation wiring).

## Test ledger
- Base (origin/main 74f19ac): batch-21 closed at 985 collected non-slow; confirm at Phase-3 entry.

## Decision log
- 2026-07-01 P0: batch-22 init, US-030+031 scope, RC-1 PASS (74f19ac), geometry measurement spike dispatched.
