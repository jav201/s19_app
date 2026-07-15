# 02 — Phase-2 Cross-Review — batch-45 (Memory-Map Band-Bands entropy view)

Triple review (architect + qa + security). **Security: OK-to-ship, low-surface render-only; hold C-17
on the retained A2L detail path.** Outcome: **iterate-to-refine → fold (autonomous, no story-kill, no
HIGH security) → re-gate APPROVE.**

## Findings + resolutions (folded)

### Blockers (closed by fold)
- **B1 — entropy set-site (architect B1 / qa B2).** The AT fixture `_install_case_02_loaded_file` calls
  `build_loaded_s19` directly and never runs `_apply_prepared_load`, so an app-state mirror leaves
  entropy empty in every map AT. **FOLD:** add `LoadedFile.entropy_windows: list[EntropyWindow] =
  field(default_factory=list)` (models.py, non-frozen); compute `compute_entropy(mem_map)` inside
  `build_loaded_s19` + `build_loaded_hex` (services/load_service.py, non-frozen); `update_memory_map`
  passes `self.current_file.entropy_windows` as the new render_ranges arg. Renderer computes nothing
  (thread split preserved; AT fixtures get entropy free via the real loader).
- **B2 — fixture can't span required bands (qa BLOCKER-1).** `compute_entropy(case_02)` = {low:3,
  medium:1} all low-confidence; `public_triple` has no constant/padding. **FOLD:** AT-069/070/072/073
  use a NEW seeded helper `_two_band_loaded()` — a 0xFF-fill block ≥256 B (→ constant/padding, H<1) +
  a seeded-PRNG block ≥256 B (→ high/random, H≥7.2), non-adjacent (gap so no merge), built via
  `build_loaded_s19` so entropy is loader-computed; assert bands with `compute_entropy` in-test.
- **B3 — 01/01b A2L-symbol contradiction (architect B2).** **RESOLVE:** NEW surfaces (region rows
  `addr·size·band`, At-a-glance, band legend) carry NO file-derived text. The batch-43 A2L-symbol
  detail-pane naming (R-TUI-041 R-3) is RETAINED and keeps its `safe_text`/`symbol_list_text` path
  (screens_directionb.py:1446-1451/585-618). `security_required = true` ONLY as a regression guard on
  that retained path (no new hostile sink). Fix 01b wording. No new hostile-name AT beyond reworked at036f.

### Majors (folded)
- **M1 — at036 per-AT disposition.** RETIRE: at036a arrow-focus + `test_at036_arrow_moves_cell_focus` +
  at036b two-step open (superseded by AT-074). MIGRATE to new detail/region surface: at036c/d/e detail
  chips + at036g addressless exclusion. **MIGRATE + KEEP as C-17 regression guard:** at036f
  hostile-symbol markup safety (do NOT drop).
- **M2 — Inc-2 file count.** compute-on-load adds models.py + load_service.py → Inc-2 = 5 files
  (models.py, load_service.py, screens_directionb.py, app.py, test_tui_directionb.py).
- **M3 — MapCell/grid disposition.** DELETE (dead after band bar replaces grid): `MapCell`(+`.Selected`),
  `adjacent_cell_index`/`focus_adjacent_cell`/`_ADJACENT_*`, `#map_grid`/`#map_content`/
  `#map_open_hex_button`. In Inc-5 (grid+modal retirement); added to C-26 census.
- **M4 (qa) — off-thread compute unguarded.** `update_memory_map` AST-purity guard (`test_tc028`,
  test_tui_directionb.py:4471) omits `compute_entropy`. **FOLD:** add `compute_entropy` (+ new entropy
  helper) to `forbidden_calls` in Inc-2.

### Minors (folded)
- m1: §6.5 reword — stats strip RETAINED UNCHANGED (already `#map_stats`, independent of cell colour;
  `coverage_stats` screens_directionb.py:660-739). Validity signal intact.
- m2: TC renumber TC-045.1..6 → **TC-060.1/.2/.3/.4 + TC-061.1/.2 + TC-062.1** (kills TC-045 collision
  with batch-01/07).
- m3: AT-074 pilot.click precedent = test_tui_patch_editor_v2.py:3198 / test_tui_variants.py:406 (real
  `pilot.click`), not AT-036b. RED still real (RegionRow new → pre-fix 2-step only).
- security F2: reword 01b coverage-cut note to name the retained safe path.

## Revised increment cut (≤5 files each)
1. **Inc-1** — entropy_style.py (`ENTROPY_BAND_CLASS`/`_GLYPH`/`_MEANING`) + styles.tcss `.band-*` +
   tests/test_entropy_style.py (census: every ENTROPY_BANDS label has a full entry). [3]
2. **Inc-2** — compute-on-load (models.py `entropy_windows` + load_service.py both loaders) + band bar +
   region list + `_merge_band_runs` (screens_directionb.py) + `update_memory_map` wiring (app.py) +
   RED-first AT-069/070/071 + `_two_band_loaded` + AST-purity-guard update (test_tui_directionb.py). [5]
3. **Inc-3** — single-click nav (RegionRow.on_click→OpenInHexRequested; screens_directionb.py) + AT-074
   real pilot.click (test_tui_directionb.py). [2]
4. **Inc-4** — At-a-glance histogram+sparkline (screens_directionb.py `#at_a_glance`) + styles.tcss
   pilot-measured dock (80×24/120×30) + AT-072/073 + TC-061.x (test_tui_directionb.py). [3]
5. **Inc-5** — retire modal + grid: screens.py (del EntropyViewerScreen/EntropyCell/ENTROPY_BAND_COLOUR/
   ENTROPY_MAX_ROWS/MapCell/arrow-nav) + app.py (del action/callback/binding/import) + styles.tcss (del
   #entropy_*/.map-cell/#map_grid) + delete tests/test_tui_entropy_viewer.py + test_tui_snapshot.py
   (drop tc036s, xfail tc016s map cells) + AT-075/076 + at036 rework/retire. [5]
6. **Inc-6** — REQUIREMENTS.md (add R-TUI-060/061/062; amend R-TUI-041; retire R-TUI-050/051 §6.5) +
   test_loadfilescreen_input.py:50 comment. [2]
+ post-merge canonical-CI snapshot regen follow-up PR.

## Re-gate — axis check (autonomous APPROVE)
Coverage: US→AT (069-076) + LLR→TC (060.x/061.x/062.x) complete; every LLR targets a NON-frozen file
(0 frozen). Certainty: fixture blocker closed (seeded two-band), set-site closed
(LoadedFile.entropy_windows), every AT names a real RED counterfactual + drives the shipped surface;
off-thread contract now guarded. Evidence: seams file:line-cited across sub-reviews. No unmet axis →
APPROVE. Security PASS (hold C-17 regression on retained A2L detail at Inc-2/Inc-5). 0 story-kill.
Increment cut re-derived (C-21). Phase 3 Inc-1 dispatched.
