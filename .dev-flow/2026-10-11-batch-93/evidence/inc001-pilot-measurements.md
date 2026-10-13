# inc001 — P3 pilot measurements (C-29): the two panel-column thresholds

Recorded for batch-93 increment 001 (HLR-127.3 / LLR-129.2). Every number
below was executed, not copied (the charter's own rule). The values live IN the
code as named constants with these notes:

- `s19_app/tui/screens_directionb.py::_STATS_FULL_MIN_WIDTH = 84`
- `s19_app/tui/screens_directionb.py::_REGION_ROW_MICROBAR_MIN_WIDTH = 43`
- `s19_app/tui/screens_directionb.py::_MAP_PANEL_TO_ROWS_INSET = 51`

## The ~84 stats threshold (LLR-129.2)

Method: the full one-line form was composed with the shipped formatter against
the charter demo fixture (5376 B mapped over 5 ranges, span 0x1FFF0200):

    Mapped 5.2 KiB / 511.9 MiB span (0.0010%) · 5 ranges (5 valid) · 4 gaps · 0 issues

- Full form: **84 cells** (leading pad included) — matches the contract's P1
  measurement of the variant-C capture row 23 exactly.
- Compact form (shortened labels only, same seven statistics): **66 cells** —
  clears the 68-column stats strip the 80x24 floor geometry admits
  (strip measured 68 there; full form would wrap).

Decision: the strip's measured width ≥ 84 → full form; below → compact. The
threshold IS the full form's own measured width (the contract's derivation).
Boundary limb: at exactly 84 the full form renders, at 83 the compact —
`tests/test_tui_map_big.py::test_tc662_stats_threshold_boundary_limb`.

## The ~43 microbar threshold (LLR-127.3)

Method (two axes, C-29):

1. Executed the row formatter: the microbar row measures **40 cells**, the
   compact row **35 cells**
   (`tests/test_tui_map_big.py::test_tc660_row_widths_pin_the_threshold`).
2. Grid-reconstructed the charter captures for the left pane's content width:
   - `memmap2_map_C.120w.svg` (120x36): content **41 cols** → microbar ABSENT
     (matches the capture: no `░░░░` segments in the region rows).
   - `memmap2_map_C_160x48.120w.svg` (160x48): content **81 cols** → microbar
     PRESENT (matches: `256 B ░░░░` rows).

The threshold must satisfy 41 < T ≤ 81. **T = 43** is the smallest value
consistent with both capture limbs while keeping the 40-cell row ~3 columns
inside the available width. Recorded limbs:
`tests/test_tui_map_big.py::test_tc660_microbar_drops_below_the_threshold`
(absent at the 41-col 120x36 pane, present at the 81-col 160x48 pane, with the
surviving fields' parsed offsets identical in both limbs).

## The panel→rows inset (the 43-threshold's basis)

Measured on the SHIPPED layout at 120x36: panel content 92 cols, left-pane
content 41 → inset **51** (panel padding 4 + inspector 44 + gutter 1 + pane
border/padding 4 − 2 measurement slop, recorded in the constant's note). The
cockpit decision reads `panel.size.width - 51` at render time. Limitation
recorded in the constant: the STACKED narrow regime (80x24, LLR-041.10) hands
the left pane the full width, so the inset over-subtracts there and the floor
rows render microbar-free; the regime-aware re-derivation is HLR-131's (a
later increment).

## The 33-cell peek (HLR-128) — re-derived

`00000000  08 00 12 00 08 00 16 00` = 8 + 2 + 8×3 − 1 = **33 cells**; the
shipped 16-byte row measured 79 cells (P-1's executed method). The peek-row
count is cut from the measured inspector height minus the 6 field rows,
floored at 1: rendered counts 1 (100x30) < 5 (120x36) < 17 (160x48) —
monotone (`test_tc661_peek_row_count_is_monotone_in_pane_height`).

## Render verification

`.dev-flow/2026-10-11-batch-93/evidence/inc001_render_check.py` drives the
shipped screen at 100x30 / 120x36 / 160x48 and prints the cockpit facts; its
saved frames `inc001-map-120x36.svg` / `inc001-map-160x48.svg` show the layout
matching the variant-C capture (pane titles/subtitles, chips `· 1 19% ░ 1 5%
▒ 4 57% ▓ 3 19%`, fixed-width rows, 8-byte peek, always-visible stats line).
