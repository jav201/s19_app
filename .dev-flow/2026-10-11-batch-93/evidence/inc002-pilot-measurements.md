# inc002 — the re-measured thresholds + the wrap-audit findings (C-29)

Recorded for batch-93 increment 002 (HLR-130 / HLR-131). Every number below
was EXECUTED on the shipped tree (probes in this directory), not copied.

## The stack threshold: `_MAP_STACK_MIN_WIDTH = 86` panel columns

The contract estimated ~84 panel columns ("re-measured at P3 and recorded" —
this is that re-measurement). Derivation, executed:

- Side-by-side, the row widget's width measures `panel - 51` (the inc-001
  inset re-verified: panel 90 → widget 39 at 120x36; panel 130 → 79/81 at
  160x48 by scrollbar presence).
- The compact row (the form the 43-column microbar gate admits below panel
  94) measures 35 cells (inc-001's executed formatter pilot, re-used).
- The threshold is the SMALLEST panel width at which the compact row still
  fits its widget: 51 + 35 = **86**.
- At panel 86 (terminal 98): the widget measures 35 with the list's 2-col
  scrollbar, 37 without (the inset's "2-column slop" IS the scrollbar) — the
  35-cell row fits both limbs. At 85 the side-by-side widget would be 34/36;
  the 34 limb wraps — so 85 and below STACK.

Boundary arms (TC-673): terminals 95/96/97/98/99 → panels 83/84/85/86/87 —
stacked below, side-by-side at/above, every arm under a NARROW workspace
class (the terminal-keyed negative control). The panel↔terminal mapping
(panel = terminal − 12 below the 120-col breakpoint; − 30 above) was measured
across terminals 60..120 (`inc002_regime_probe.py`).

## The stacked inset: `_MAP_PANEL_TO_ROWS_INSET_STACKED = 8` panel columns

Measured panel − row-widget at four stacked geometries: 60x24 (48−40),
80x24 (68−60), 80x30 (68−60), 90x30 (78−70), 94x40 (82−76 with no scrollbar)
— exactly 8 wherever the list's scrollbar renders; the painted widget is the
2 scrollbar columns wider when the rows do not overflow (the GATE keeps the
conservative −8 in both cases; the painted width is what the wrap audit
asserts). This closes inc-001's recorded limitation: the 80x24 floor rows now
carry the microbar (widget 60 ≫ 43), matching the capture limbs' logic in
both regimes.

## The microbar/stats thresholds

Unchanged from inc-001 (43 / 84); the 43-gate now picks its inset per regime
via the shared `_is_stacked_width` predicate, so the rows' form can never
disagree with the layout regime.

## The wrap audit's findings on the shipped inc-001 tree (all fixed at authorship)

Probe transcripts: `inc002_probe.out.txt` (before) / `inc002_probe_after.out.txt`
(after). Defects found:

1. **Inspector A2L symbol names wrapped mid-content** (file-derived, unbounded
   length): an 82-cell name in the 38-col side-by-side interior, a 202-cell
   name at both regimes — `MemoryMapPanel._build_inspector_text`. Fixed via
   the house clip seam `_clip_to_cells` (cell_len/set_cell_size + ellipsis,
   mirroring `S19TuiApp._clip_to`) against `_inspector_body_width()`.
2. **The audit caught the fix's own first defect**: the clip budget ignored
   the inspector's vertical-scrollbar gutter (a 40-cell clipped line in the
   38-col painted budget at 100x30) — the budget now subtracts
   `_INSPECTOR_SCROLLBAR_GUTTER` (2, measured) unconditionally, which is safe
   exactly because the scrollbar appears when a long name overflows.
3. **The pre-selection hint wrapped at every side-by-side geometry** (59-cell
   one-liner in the 40-col interior): re-authored as two lines (29/28 cells)
   joined through `Text` directly — `safe_text`'s C0 scrub would eat the
   newline (the house rule: newlines join Text lines directly).

Zero overflows across 80x24 / 100x30 / 120x36 / 140x40 / 160x48 after the
fixes (transcript: `inc002_probe_after.out.txt`); the harness's counterfactual
(LLR-130.2) fails on an injected over-long line and is clean without it
(TC-670).

## HLR-131's re-apportionment, executed

`inc002_boundary_probe.py`: live resizes 160x48 → 120x36 → 96x30 → 160x48
cross the microbar threshold (79→39) and the stack threshold (panel 90→84);
after every leg the bar re-apportions to the grid content, the rows rebuild
to the gate's form, the peek re-cuts (17 → 5 → 1 → 17 rows), the stats
re-render — 0 stale surfaces, 0 band-segment overflows.

One shipped-path hardening fell out of the resize work (measured, not
theorized): a render that runs BEFORE the panel's first layout is
re-apportioned when the measured width arrives, and the deferred
auto-selection could bind the SUPERSEDED row list — with removal AND mount
both deferred, exactly one registered list can still be the stale one, and
Textual re-homes the focus to None when that list vanishes (the b77 key-walk
family at the 80x24 floor). Fixes in `MemoryMapPanel`: the width flip re-runs
`render_ranges` itself (single selection authority, generation-guarded); each
`.map-region-list` is stamped with its render generation and
`_apply_auto_selection` resolves only the stamp-matched list (bounded retry);
focus is taken synchronously through `Screen.set_focus` (the deferred
`Widget.focus()` callback was measured dropping inside the transition); and
the width-0 pass arms exactly one bounded retry (LLR-131.3).

Three test-side re-aims ride the same measurement (the inc-001 precedent —
test-side settle for a real timing change, assertions untouched):
`_settle_selection` in `test_tui_map_big.py` now waits for focus to rest on
a LIVE row (settling on the selection alone reads mid-transition), with a
selection-only signal while the map screen is hidden (AT-B77-12's focus
guard); `test_b01_region_click_snaps_hex_to_far_range` settles the deferred
auto-selection — and the focus scroll it schedules — before the gesture
(measured: the `call_later` scroll landed between the hit-test poll and the
double-click ~1 in 3 runs, navigating to range A instead of B); and the
shared click helpers bind their target from the panel's LIVE rows, never
`app.query(RegionRow).first` (which can match a superseded render's row).

## Snapshot baselines

NOT regenerated: both map cells pass unchanged — the 80x24 capture's fold
shows the overview stack (the region rows with their new floor microbar sit
below the pinned viewport top), and the 120x30 cell is side-by-side in both
the old and the new law with identical row limbs. Verified by running the two
map snapshot cells green.
