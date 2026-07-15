# Increment 2 — core Memory-Map entropy view swap (R-TUI-060 LLR-045A.2/.3/.4/.5/.6)

Split into 2a (RED tests + superseded-test disposition) + 2b (5-file impl).

1. **What changed:** entropy computed once on the worker-thread load path
   (`LoadedFile.entropy_windows` set in `build_loaded_s19/hex`), cached; the map render swaps the
   `sev-*` validity cell grid for a proportional band bar + per-region list + band legend (per-run
   widgets carrying `band-{token}` classes from entropy_style, `safe_text` content; region rows
   `{glyph} 0x{start:08X} · {bytes} B · {band}`, addr/size/band only — no A2L text, B3). ~14
   superseded grid tests dispositioned (rework at035/at036e→pure/at036f→pure hostile-symbol; retire
   cell-grid/arrow-nav/tooltip/count/fill; defer at036b/tc041_6 to Inc-3).
2. **Files:** 2a: test_tui_directionb.py, test_tui_snapshot.py. 2b: models.py, services/load_service.py,
   app.py, screens_directionb.py, styles.tcss.
3. **How to test:** `pytest tests/test_tui_directionb.py -q`; C-27 dual-guard; consumer suites.
4. **Results:** RED captured (AT-069/070/071 fail pre-impl). Full file **163 passed / 2 skipped**;
   LoadedFile consumers 77 passed; C-27 0 frozen diffs; entropy_style census green; 2 map cells xfail;
   ruff clean. Ledger +~4 net (new ATs + gap test − retired, +xfail/skip).
5. **Risks:** DuplicateIds re-render bug FOUND+FIXED (id→class) + guarded (`test_map_band_view_survives_rerender`). MapCell/arrow-nav now dead (deleted Inc-5). `#map_detail` idle until Inc-3 re-wire. **B-01** nearest-present-row snap coverage dropped with `test_ac1` → **carried to Inc-3** (update_hex_view unchanged, no active regression).
6. **Pending:** Inc-3 re-wire region-row→detail/open-in-hex + re-cover B-01 + unskip 2 deferred; Inc-5
   delete MapCell + dead helpers + `.map-cell` tcss; post-merge snapshot regen (2 map cells).
7. **Next:** Inc-3 — single-click region→hex nav (R-TUI-062) + region-row selection detail.

Code-review: APPROVE-WITH-NITS, 0 HIGH. F1 (MEDIUM, real correctness: cross-gap same-band merge) FIXED
+ gap test (RED-if-revert confirmed). F2 (AST guard bare-name) FIXED. F4 (docstring id/class drift)
FIXED. F3 (B-01) → Inc-3. C-17 preserved (build_detail_text + hostile test live; reworked at036f).
Security: no handoff (region/band/legend carry no file-derived text; safe_text). Axis check clean →
APPROVE.
