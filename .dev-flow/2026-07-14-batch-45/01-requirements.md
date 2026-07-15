# Requirements Document — s19_app — Batch 2026-07-14-batch-45

Memory-Map ENTROPY "Band-Bands" view (field-audit N1/U3/N3) + retire the entropy pop-up.
Origin: operator-approved prototype `prototypes/memory_map_entropy.prototype.py` (Variant 3 · BAND BANDS).

## §2.6 Source user stories (Phase-0 READY)

- **US-045a (N1/U3):** As an engineer inspecting a firmware image, I want the Memory Map to show
  per-region ENTROPY as a proportional segmented band bar (contiguous same-band runs, width ∝ byte
  size) + a per-region list (address · size · band), each coloured AND textured by band, so I can see
  at a glance which regions are code/calibration/tables/padding. Observable: a real image renders
  coloured+textured band segments + a region list where the map was previously all grey.
- **US-045b (U3):** I want a docked "At a glance" panel (per-band count/% histogram + profile
  sparkline) for a whole-file summary.
- **US-045c (N3):** I want a single click on a region to reposition the hex view to that region's
  start address (today it takes two clicks).
- **US-045d:** The standalone entropy pop-up is removed; its function (band classification, paging,
  sort, legend) is superseded by the always-visible map view. Requires §6.5 amendments on
  R-TUI-041 (amend) + R-TUI-050 / R-TUI-051 (retire).

DoR: all four READY (RC-1 PASS @ a015e28; N1 verified NOT-IMPLEMENTED; EntropyViewerScreen verified present to retire).

---

_Normative spec below = Phase-1 architect derivation (IEEE 830 + EARS). QA strategy + AT registry:
`01b-qa-strategy-and-verification.md`._

## §2 Scope & Constraints

In scope: US-045a band bar + textured region list; US-045b docked At-a-glance histogram+sparkline;
US-045c single-click region→hex; US-045d remove EntropyViewerScreen + its `e` binding + entry point.
Out: prototype Variants 1/2 (rejected); band-run merge-tolerance heuristic (Phase-2 risk R4); any
change to `entropy_service.compute_entropy` / `ENTROPY_BANDS` (reused verbatim).

Hard constraints:
- **C-FRZ** engine-frozen set OFF-LIMITS. C-27 dual-guard each increment; expected frozen diff = 0.
- **C-COLOUR** entropy bands are a NEW dimension (not severity) → own band→style map in NEW non-frozen
  `s19_app/tui/entropy_style.py`; do NOT edit color_policy.py; css_class_for_severity read-only.
- **C-17** band labels constant (safe); any file-derived text (batch-43 A2L symbol names) via
  `safe_text`/`Text`, never an f-string markup sink.
- **C-23** band bar + docked At-a-glance must fit 80×24 AND 120×30 — pilot-measured LLR, not fr-math.
- **C-22** snapshot drift = upper bound under `strict=False`; canonical-CI regen only.
- **QA hard constraint:** each band distinguished by a texture glyph AND/OR `band-*` CSS class — NOT
  colour alone (headless `.render()` doesn't expose ANSI colour → colour-only violates C-10).

Snapshot accounting (verified): drift+regen = `test_tc016s_density_layout_snapshot`
`map-comfortable-80x24`+`-120x30` (2); delete = `test_tc036s_entropy_modal_snapshot`
`entropy-comfortable-80x24`+`-120x30` (2, removed with the modal).

## §3 Acceptance blocks (black-box; AT bodies in 01b)

- **AC-045a** — surface `MemoryMapPanel`/`#memory_map_panel` via `update_memory_map`. AT-069 (high
  region→high-band glyph+class), AT-070 (constant region→DIFFERENT band token, C-10 two-branch),
  AT-071 (region list addr·size·band rows).
- **AC-045b** — `#at_a_glance`. AT-072 (per-band count/% match tally), AT-073 (sparkline tracks data:
  mixed varies, constant uniform).
- **AC-045c** — region row `on_click`→`OpenInHexRequested`→handler→`update_hex_view` (reused). AT-074
  (one real `pilot.click`→hex repositions; C-12/C-16).
- **AC-045d** — AT-075 (`e` opens no modal + map band legend present), AT-076 (EntropyViewerScreen not
  importable + `action_show_entropy`/`e` binding absent).

## §4 HLR + LLR (EARS "shall")

New locked ids **R-TUI-060/061/062**. Batch HLR ids HLR-045A..D. New module `entropy_style.py`.

### R-TUI-060 (HLR-045A) — Entropy band visualization (US-045a)
The Memory Map shall present per-window entropy (from `compute_entropy`, render-only) as (a) a
proportional segmented band bar (contiguous same-band windows merged, width ∝ summed bytes) and (b) a
per-region list (start · size · band), colour- AND texture-coded via non-frozen `entropy_style` —
never the frozen `sev-*` map.
- LLR-045A.1 NEW `entropy_style.py`: per-band `band-*` class + glyph (`·/░/▒/▓`) + meaning; missing
  entry fails a census test.
- LLR-045A.2 `render_ranges` accepts pre-computed windows; merges contiguous same-band into runs
  `(band, bytes, start)` — pure `_merge_band_runs`, no re-parse.
- LLR-045A.3 render each run as `glyph×max(1, round(bar_w·bytes/total))` styled by band class,
  markup-safe `Text` (`_render_band_bar`; `.band-*`).
- LLR-045A.4 one region row per run `0x{start:08X} · {bytes} B · {band}`, band-styled, markup-safe.
- LLR-045A.5 empty/no-file → neutral no-data note, no segments, no raise.
- LLR-045A.6 windows computed off the UI thread on load, handed pre-computed (thread split); exact
  set-site **assumed — verify Phase 2** (`_parse_loaded_file`/`_apply_loaded_file`; maybe
  `LoadedFile.entropy_windows`).

### R-TUI-061 (HLR-045B) — "At a glance" panel (US-045b)
The Memory Map shall present, docked beside the bar, per-band count+% histogram + profile sparkline,
render-only from the same windows + `entropy_style`.
- LLR-045B.1 per-band tally → histogram rows (glyph+label+bar+NN%), band-styled (`#at_a_glance`).
- LLR-045B.2 sparkline maps window entropy (0–8)→ 9-glyph ramp ` ▁▂▃▄▅▆▇█`, band-coloured; step
  `max(1, N//width)`.
- LLR-045B.3 width<120 → panel reflows (stacks below bar) via `width-narrow`; docked layout
  **pilot-measured** at 80×24 + 120×30 (C-23).

### R-TUI-062 (HLR-045C) — Single-click region→hex nav (US-045c)
When the operator clicks a region, the Memory Map shall reposition the hex view to that region's start
+ switch to Workspace/hex in one action, reusing `OpenInHexRequested`→handler→`update_hex_view`.
- LLR-045C.1 region `on_click` posts `OpenInHexRequested(start)` directly (no reveal button).
- LLR-045C.2 app handler unchanged; coarse starts snapped by `_snapped_focus_row_index`.
- LLR-045C.3 click on padding beyond last segment = inert no-op (guard).

### R-TUI-041 AMENDED + HLR-045D retirement (US-045d)
The standalone entropy viewer shall be removed (no `EntropyViewerScreen`, no `e`→entropy binding, no
entry point); the map band view provides the equivalent → paging/sort superseded.
- LLR-045D.1 delete `EntropyViewerScreen`, `EntropyCell`(+`.Selected`), `ENTROPY_BAND_COLOUR`,
  `ENTROPY_MAX_ROWS`, all `#entropy_*` (screens.py; styles.tcss).
- LLR-045D.2 remove `action_show_entropy`, `_focus_entropy_target`, `Binding("e","show_entropy")`,
  the import (app.py:49,802,4600-4658).
- LLR-045D.3 map band legend iterates `entropy_style` (single source, census-guarded); markup-free.
- LLR-045D.4 delete `tests/test_tui_entropy_viewer.py` + `test_tc036s` cells; regenerate 2
  `map-comfortable-*` baselines in canonical CI.

**C-26 touched shared symbols (Phase-2/3 reverse-grep):** screens_directionb.py `MemoryMapPanel`,
`MapCell`(+`.Selected`), `OpenInHexRequested`(reused), `render_ranges`, `cell_status`,
`status_to_css_class`, map ids, `.map-cell`; NEW `RegionRow`, `#map_region_list`, `#at_a_glance`,
`#map_band_legend`. app.py `update_memory_map`, `on_memory_map_panel_open_in_hex_requested`,
`_snapped_focus_row_index`, `action_show_entropy`(del), `e` binding(del). screens.py
`EntropyViewerScreen`/`EntropyCell`/`ENTROPY_BAND_COLOUR`(del). entropy_service.py read-only.
styles.tcss `.band-*` add / `#entropy_*` remove. Tests: rework `at036a..g` map arrow-nav ATs
(superseded — rework NOT silent drop); retire `test_tui_entropy_viewer.py`; snapshot regen/delete.

## §6.5 Requirement amendments (Before → After / Deleted / New)

- **R-TUI-041 AMENDED** — cell colour dimension validity(`sev-*`)→entropy band (`entropy_style`,
  non-frozen) as segmented bar + textured region list; detail/nav (HLR-036) two-step→single click;
  coverage stats strip (HLR-037) RETAINED (moves off cell colour to `#map_stats`); render-only
  contract + `width-narrow` reflow preserved. Reason: field-audit N1; operator prototype V3.
- **R-TUI-050 DELETED** — paging/sort superseded by all-regions-at-once map. Tests AT-062a/b,
  TC-324/325 removed.
- **R-TUI-051 DELETED** — legend + clickable strip superseded by map band legend + single-click
  region→hex; `ENTROPY_BAND_COLOUR` retired. Tests AT-063a/b, TC-326/327 removed.
- **R-TUI-035 / R-TUI-036 — NO CHANGE (explicit):** verified unrelated to entropy (`:893` command-bar
  clipboard; `:903` issues rail); brief conflated them with internal HLR-035/036 in R-TUI-041.
- **NEW:** R-TUI-060, R-TUI-061, R-TUI-062.

## §5 Feasibility, risks, increment cut

Feasibility HIGH. Risks: R1 modal-removal reach (grep-gate=0 post-retire); R2 map arrow-nav ATs
superseded (rework not drop); R3 entropy compute on load (worker-thread cache; verify site Phase 2);
R4 band-run fragmentation (ship plain runs; merge-tolerance fast-follow only if Phase-4 clutters); R5
colour-source drift (NEW entropy_style; delete ENTROPY_BAND_COLOUR); R6 snapshot canonical-only; R7
entropy_service purity preserved.

Increment cut (≤5 files): Inc-1 entropy_style + `.band-*` + census [3]; Inc-2 band bar + region list +
compute-on-load + RED-first AC-045a [3]; Inc-3 At-a-glance + pilot-geometry [3]; Inc-4 single-click nav
[2, foldable into Inc-2]; Inc-5 retire modal [5]; Inc-6 REQUIREMENTS.md amendments [2]. Snapshot regen
= post-merge follow-up PR.
