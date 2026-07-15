# Traceability Matrix — s19_app — Batch 2026-07-14-batch-45

Memory-Map entropy Band-Bands view. All nodes in `tests/test_tui_directionb.py` unless noted.

| Requirement | HLR/LLR | Layer A (TC, white-box) | Layer B (AT, black-box) | Code (non-frozen) | Status |
|---|---|---|---|---|---|
| **R-TUI-060** band bar + textured region list | HLR-045A / LLR-045A.1–.6 | TC-060.x (test_entropy_service.py band compute) + census (test_entropy_style.py, 8) + `test_map_band_view_survives_rerender` | AT-069 :3911 · AT-070 :3941 (C-10) · AT-071 :3982 · AT-071b :4014 (gap-merge) | entropy_style.py (new) · screens_directionb.py · services/load_service.py · models.py · app.py · styles.tcss | Automated |
| **R-TUI-061** At-a-glance histogram + sparkline | HLR-045B / LLR-045B.1–.3 | TC-061.1 :4322 · TC-061.2 :4344 · AT-073b :4454 (C-23 geometry) | AT-072 :4372 · AT-073 :4421 (two-branch) | screens_directionb.py · styles.tcss | Automated |
| **R-TUI-062** single-click region→hex | HLR-045C / LLR-045C.1–.3 | TC-062.1 :4157 · `test_b01_region_click_snaps_hex_to_far_range` :4198 | AT-074 :4121 (C-12/C-16 real pilot.click) | screens_directionb.py (RegionRow; app handler reused) | Automated |
| **R-TUI-041** AMENDED (cell colour validity→entropy band; two-step→single-click; stats strip retained; R-3 A2L naming re-wired) | HLR-045D / LLR-045D.3 | — | `test_at_r3_region_click_detail_names_a2l_symbol_literally` :4240 (C-17 live path) | screens_directionb.py | Amended |
| **R-TUI-050** RETIRED (paging/sort) | HLR-045D / LLR-045D.1/.2/.4 | — | AT-076 :4551 (removal guard) | screens.py/app.py (deleted) | Retired |
| **R-TUI-051** RETIRED (legend + clickable strip) | HLR-045D / LLR-045D.1/.3 | — | AT-075 :4514 (e→no modal + legend) · AT-076 :4551 | screens.py/styles.tcss (deleted) | Retired |

**Gate:** 1374 passed / 0 failed / 23 xfailed (20 batch-45 baseline-drift for canonical-CI regen + 3
pre-existing) / exit 0. C-18: 9/9 AT = one on-disk node. C-27: 0 frozen diffs. C-17 preserved on the
live region-detail path.
