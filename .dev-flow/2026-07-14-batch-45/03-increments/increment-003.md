# Increment 3 — single-click region→hex nav + detail re-wire (R-TUI-062 LLR-045C)

1. **What changed:** region-list rows become single-click nav targets. New `RegionRow(Static)`
   (`on_click` → `RegionRow.Activated(region_start,region_end)`); `MemoryMapPanel.on_region_row_activated`
   derives status via `cell_status` (no re-parse), populates `#map_detail` via the RETAINED
   `build_detail_text` (keeps batch-43 R-TUI-041 R-3 A2L-symbol naming + its C-17 markup-safety guard
   on a LIVE path), then posts `OpenInHexRequested(start)`. The `OpenInHexRequested` message + app
   handler `on_memory_map_panel_open_in_hex_requested` (with `_snapped_focus_row_index` B-01 snap) are
   REUSED UNCHANGED — no app.py edit. Padding/legend/empty click = no-op (only RegionRow posts nav).
2. **Files (2):** screens_directionb.py, tests/test_tui_directionb.py. (app.py NOT touched.)
3. **How to test:** `pytest tests/test_tui_directionb.py -q`; C-27; snapshot.
4. **Results:** **169 passed / 0 skipped** (+6; 2 deferrals unskipped/reworked). C-27 4 passed 0 frozen;
   2 map cells xfail; ruff clean. AT-074 RED captured (neutered on_click → nav posts nothing → failed;
   restored → green).
5. **Risks:** B-01 region-click uses a present start (exact-match branch); the absent-in-gap branch
   re-covered by a direct `update_hex_view(absent)` in the same test. `#map_open_hex_button` now
   dead (removed Inc-5).
6. **Pending:** Inc-5 delete MapCell + arrow-nav + dead `#map_open_hex_button` + `.map-cell` tcss +
   unused cell helpers; post-merge snapshot regen.
7. **Next:** Inc-4 — docked "At a glance" histogram + sparkline (R-TUI-061).

Review: orchestrator diff-review (low-risk 2-file, reused handler, RED captured) — RegionRow/detail
re-wire matches spec; C-17 on live path; app.py + frozen untouched. APPROVE. Independent agent review
reserved for Inc-5 (the deletion). Axis check clean.
