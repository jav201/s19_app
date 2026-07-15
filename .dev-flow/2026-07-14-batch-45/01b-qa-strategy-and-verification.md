# 01b — QA Strategy & Verification — batch-45 (Memory-Map Band-Bands entropy view)

BLUF. All four stories are black-box observable through `#screen_map` via Textual Pilot. New ATs
occupy **AT-069 … AT-076** (highest prior AT-068). Hard QA constraint on dev: **band differentiation
must carry a non-colour token (texture glyph and/or `band-*` class), not colour alone** — headless
`.render()` doesn't expose ANSI colour, so a colour-only bar is un-assertable (C-10). No story flagged
un-observable.

## 1. Validation method per requirement
- US-045a band bar+region list → **test (pilot)** (content-derived render; drive `update_memory_map`
  over a mixed image, read mounted segment/row widgets; TC-045.x white-box support, not the gate).
- US-045b At-a-glance histogram+sparkline → **test (pilot)** (counts asserted against actual band
  distribution, C-10).
- US-045c single-click → **test (pilot)** (real `pilot.click` C-16, observe `#hex_view` repositioned
  C-12; reuses AT-036b hex-row-token read).
- US-045d retirement → **test (pilot) + inspection** (Pilot: `e` opens no modal + map legend present;
  import/attr guard: screen+action gone; **analysis** for snapshot-cell retirement via canonical CI).
- R-TUI-041/050/051 amendments → **inspection** (Phase 4/6 REQUIREMENTS rows move).

## 2. AT registry (black-box, Layer B) — all in tests/test_tui_directionb.py (map-panel AT home; helpers `_mounted_map_panel`/`_install_case_02_loaded_file` at :3232+), except AT-076 import guard also touches test_tui_entropy_viewer.py (retire)

Fixture note: `_install_case_02_loaded_file` must span ≥2 bands (a `0xFF`-fill constant/padding region
+ an incompressible/random high region); verify vs `compute_entropy(mem_map)`, else seed a purpose
mem_map (mirrors snapshot `_entropy_run_before`, test_tui_snapshot.py:369).

- **AT-069** high region renders HIGH band token — segment/row over high-entropy region carries the
  high glyph + `band-high/random` class + label. RED: pre-fix uniform `MapCell` grid coloured `sev-*`,
  no band glyph/class/text.
- **AT-070** constant region renders a DIFFERENT band token than high (C-10 two-branch) — same render,
  compare two region tokens; glyph AND class differ. RED: pre-fix both identical (validity-driven).
- **AT-071** region list shows addr·size·band rows — N rows = merged-region count; a row's text has
  `0x{start:08X}` + size + band. RED: pre-fix has detail hint + stats but no per-region list.
- **AT-072** histogram per-band count/% match tally — one entry per occupied band; high & constant
  counts ≥1 and equal region tallies; %s ~100. RED: pre-fix no histogram surface.
- **AT-073** sparkline tracks data — mixed image sparkline has ≥2 distinct glyphs; constant image
  uniform (single glyph). RED: pre-fix no sparkline / a fixed sparkline fails the constant branch.
- **AT-074** single real click repositions hex — `pilot.click(region_row)` (scroll first) → Workspace/
  hex revealed AND `#hex_view` render contains 16-aligned row token for region start; exactly ONE
  click. RED: pre-fix needs two (select cell, then press `#map_open_hex_button`, as AT-036b does).
- **AT-075** `e` opens no modal + map has band legend — `pilot.press("e")` leaves screen_stack
  unchanged (no EntropyViewerScreen) AND map band legend lists the four labels. RED: pre-fix `e` →
  `action_show_entropy` → push modal; pre-fix map has no band legend.
- **AT-076** entropy modal class + action removed — `EntropyViewerScreen` not importable + no
  `action_show_entropy` + no `Binding("e",...)`. RED: pre-fix all three exist.

C-18 one-node map: AT-069 `test_at069_high_region_renders_high_band`; AT-070
`test_at070_constant_vs_high_bands_differ` (reads BOTH regions); AT-071
`test_at071_region_list_rows_addr_size_band`; AT-072 `test_at072_histogram_per_band_counts`; AT-073
`test_at073_sparkline_tracks_profile` (two renders, one node); AT-074
`test_at074_single_click_repositions_hex`; AT-075 `test_at075_e_key_opens_no_modal_map_has_legend`;
AT-076 `test_at076_entropy_screen_and_action_removed`.

## 3. White-box TC plan (mapped to LLR-045.*)
- TC-045.1 region-run merging (adjacent same-band merge; band change splits; low_confidence labelled
  not dropped; empty→[]).
- TC-045.2 band→glyph/class total function (4 bands + ≥8.0 sentinel; distinct glyph AND class per
  band; no collision) — C-10 backstop for AT-069/070.
- TC-045.3 histogram counts (per-band = region count; %s sum 100±rounding).
- TC-045.4 proportional widths (∝ bytes; sum to bar width; single region fills; zero-span→empty note).
- TC-045.5 nav emission (region activation posts exactly ONE `OpenInHexRequested(start)`; no
  selection→no message).
- TC-045.6 low-confidence surfacing (distinguishable marker without changing band).

## 4. Regression checklist (Phase 4)
(1) map snapshot cells re-render → canonical-CI regen; (2) existing AT-036a-g map ATs — verify none
assert the retired grey grid (rework superseded ones, don't silent-drop); (3) frozen guards C-27
untouched (entropy_service read-only); (4) `update_memory_map` AST-purity guard
(test_tui_directionb.py:4472) still holds — renderer adds no computation.

Coverage-cut audit: empty/zero input covered by TC-045.4 (justified cut, no new AT); error/hostile =
no new untrusted-string surface (entropy is arithmetic over an already-parsed mem_map); auth N/A.
