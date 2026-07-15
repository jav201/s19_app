# 04-validation.md — batch-45 (Memory-Map entropy Band-Bands view)

**Gate verdict: PASS.** Gate run (orchestrator-owned, single complete run, C-19/C-25):
`pytest -q -m "not slow"` → **1374 passed / 2 skipped / 20 deselected / 23 xfailed / 0 failed /
exit 0** in 12:48. Shipped surface: the Memory Map screen (`#screen_map` / `MemoryMapPanel` /
`RegionRow`), driven end-to-end via `S19TuiApp` + Textual `pilot`.

## 1. Layer B (black-box) — C-18 realization gate: 9/9 AT = one on-disk node each

| AT | node (tests/test_tui_directionb.py) | observed through surface | RED counterfactual |
|---|---|---|---|
| AT-069 | `test_at069_high_region_renders_high_band` :3911 | `.map-region-row` over high block → `band-high` + `▓` + `high/random` | uniform sev-* grid, no region row |
| AT-070 | `test_at070_constant_vs_high_bands_differ` :3941 | reads BOTH rows; glyph+class differ (C-10 two-branch, one node) | no region rows, neither branch readable |
| AT-071 | `test_at071_region_list_rows_addr_size_band` :3982 | one row/run: `0x… · N B · band` | grid mounts .map-cell, 0 rows |
| AT-071b | `test_at071b_disjoint_same_band_regions_stay_separate` :4014 | two same-band blocks + gap → 2 rows (not merged 512B) | band-only merge collapses to 1×512B |
| AT-072 | `test_at072_histogram_per_band_counts` :4372 | `.map-glance-row` counts = tallies, %≈100 | no .at-a-glance surface |
| AT-073 | `test_at073_sparkline_tracks_profile` :4421 | mixed ≥2 glyphs / constant uniform (two-branch, one node) | no .map-sparkline |
| AT-074 | `test_at074_single_click_repositions_hex` :4121 | ONE real `pilot.click` → hex reveals + `#hex_view` row token (C-12/C-16) | rows exist but no click nav |
| AT-075 | `test_at075_e_key_opens_no_modal_map_has_legend` :4514 | `pilot.press("e")` → stack unchanged + band legend present | `e`→push EntropyViewerScreen |
| AT-076 | `test_at076_entropy_screen_and_action_removed` :4551 | EntropyViewerScreen/action/binding absent | all three existed |

**9/9 realized as single nodes — no blocker.** Hardening nodes: `test_map_band_view_survives_rerender`
:4064 (DuplicateIds), `test_b01_region_click_snaps_hex_to_far_range` :4198 (B-01 re-cover),
`test_at_r3_region_click_detail_names_a2l_symbol_literally` :4240 (C-17 on the LIVE region-detail
path), `test_at073b_glance_geometry_fits_and_reflows` :4454 (C-23 pilot-measured 120×30 + 80×24).

## 2. Layer A (white-box)
TC-061.1 `test_tc061_1_band_histogram_counts` :4322; TC-061.2 `test_tc061_2_sparkline_ramp_mapping`
:4344; TC-062.1 `test_tc062_1_region_activation_posts_single_open_in_hex` :4157; TC-060.x band
compute in test_entropy_service.py (unchanged, green); census test_entropy_style.py 8 nodes (LLR-045A.1).
**AST-purity guard** `test_tc028` extended: `compute_entropy` + `_merge_band_runs` added to
`forbidden_calls` (attribute AND bare-name form) → renderer is render-only; entropy computed on the
worker-thread load path (`load_service.build_loaded_*`) cached on `LoadedFile.entropy_windows`.

## 3. Bidirectional surface-reachability
IN (all via handler `update_memory_map` ← `build_loaded_*`): two-band image, disjoint same-band gap,
constant-only image, two far ranges (~1 MiB), hostile A2L symbol. OUT (observed on rendered tree /
hex): band bar/region rows, glance histogram, sparkline, hex reposition, band legend, modal-absence.
No output asserted against a bare service return.

## 4. xfail accounting (23; 0 mask a regression)
- 1–18 batch-45 **footer-drift** (`_batch45_footer_drift_marks`): removed footer-visible `e`/Entropy
  binding drifts wide-cell footers; cosmetic SVG baseline drift; behavior asserted green by §1.
- 19–20 batch-45 **map-drift** (`_batch45_map_drift_marks`): band view replaced the cell grid (intended).
- 21–23 pre-existing (test_tui_app:1784, test_tui_public_api:162, test_validation_engine:211) — predate
  the batch, untouched. All 20 batch-45 → canonical-CI regen post-merge (batch-44 lane); 0 xpassed on them.

## 5. Engine-frozen (C-27 dual-guard)
0 frozen-source diffs + 0 frozen-test-file diffs vs main (passed each increment). `entropy_service.py`
is NON-frozen — docstring-only edit; new view logic all in non-frozen screens_directionb.py/app.py.

## 6. Axis check → PASS
- Coverage: golden + two-branch + boundary/gap + far-nav + deletion/empty + geometry-floor + hostile
  markup — every US→AT + LLR→TC chain green.
- Certainty: each AT a single node with a captured RED; AST guard blocks silent inline recompute.
- Evidence: gate tail (1374 passed/0 failed/exit 0) + every claim cites a node id/file:line.

**Verdict PASS — close gate.** Carry (not a blocker): post-merge `snapshot-regen.yml` regenerates the
20 drift baselines + retires the two marker functions.
