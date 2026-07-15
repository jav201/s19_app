# Increment 4 — docked "At a glance" histogram + sparkline (R-TUI-061 LLR-045B)

1. **What changed:** new `.at-a-glance` panel docked beside the band bar (stacks below at 80×24 via
   `width-narrow`). Pure helpers `entropy_ramp_glyph` (9-glyph ramp `_ENTROPY_BAR_RAMP`),
   `band_histogram` (per-region tally → `(band,count,pct)` occupied bands), `sparkline_glyphs`
   (step `max(1,N//width)`), `_sparkline_segments` (band-run grouping for CSS colour).
   `_build_glance_widgets` renders histogram rows (`{glyph} {label} {count} {bar} {pct}%`) + a
   band-coloured sparkline. Every sink is `safe_text` over CONSTANT band labels (no file-derived
   text — B3). `.map-band-row` docks bar + glance.
2. **Files (3):** screens_directionb.py, styles.tcss, test_tui_directionb.py. (app/models/load_service
   untouched.)
3. **How to test:** `pytest tests/test_tui_directionb.py -q`; C-27; snapshot.
4. **Results:** **174 passed / 0 skipped** (+5). C-27 4 passed 0 frozen; 2 map cells xfail; ruff clean.
   AT-072/073 + geometry RED captured (glance neutered → `.at-a-glance`/`.map-glance-row`/`.map-sparkline`
   absent → all failed; restored → green). Pilot-measured: 120×30 side-by-side, 80×24 stacked, no overflow.
5. **Risks:** band bar's fixed 60-glyph content clips to ~21 cols at 120×30 (glance shares the row) —
   COSMETIC truncation, not overflow (already clipped ~50 in Inc-2/3); a responsive `_BAND_BAR_WIDTH`
   would need a snapshot regen → out of scope. Noted for postmortem.
6. **Pending:** Inc-5 delete MapCell/arrow-nav/`#map_open_hex_button`/`.map-cell` + unused cell helpers;
   post-merge snapshot regen (2 map cells now also carry the At-a-glance panel).
7. **Next:** Inc-5 — retire the entropy modal + delete the dead grid machinery (full independent review).

Review: orchestrator diff-review (3-file, pure helpers, B3-safe, RED captured, geometry pilot-measured).
No app/model/frozen change. APPROVE. Axis check clean.
