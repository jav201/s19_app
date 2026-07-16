# Increment 6 — US-MAP Memory Map BIG (R-TUI-072 / R-TUI-073 / R-TUI-074)

> batch-47 screen-upgrades Batch A. Branch `claude/screen-upgrades-handoff-0874f9`
> (HEAD = Inc-5 `71c6219`). English. Supervised-incremental, ≤5 files. This is the
> BIG tier — C-29 two-axis geometry is the dominant control (batch-46 origin).

## 1. What changed

Memory Map BIG insight layer — render-only, no parser/engine/validation change.
All values are read verbatim from the `LoadedFile` snapshot handed to
`render_ranges`; nothing is re-parsed or recomputed.

- **LLR-072.1 pastel bands + `╱` hatch gaps** — `_build_band_widgets` now draws
  the band strip proportional to the whole image ADDRESS SPACE
  (`span_end − span_start`), so unmapped gaps between runs render as `╱` hatch
  segments (`.map-band-seg .map-band-gap`, app-supplied — NOT an `entropy_style`
  band). A contiguous image (span == mapped bytes) keeps its pre-batch-47 widths,
  so only gapped images drift.
- **LLR-072.2 humanized sizes** — each region row's size renders via
  `insight_style.human_bytes` (binary, e.g. `64.0 KiB`); the inspector adds a
  `Size:` line. `build_detail_text`'s existing `"N bytes"` line is left intact
  (its byte-exact tests are preserved).
- **LLR-072.3 address ruler** — NEW `MapRuler(Horizontal)` widget mounted beneath
  the band row: exactly 5 `.map-ruler-tick` labels at 0/25/50/75/100 % of the
  span, tick 0 % == span start and tick 100 % == span end (8 hex digits, no `0x`
  prefix). Self-styled via `DEFAULT_CSS` (no `styles.tcss` edit); ticks are
  `width: 1fr` so they spread evenly across the strip.
- **LLR-073.1 size micro-bar + `N sym`** — each `RegionRow` gains a
  `microbar(run_bytes / largest_region)` and an `N sym` count of
  `_a2l_enriched_tags` addresses inside the region span, computed via the frozen
  `range_index` primitives (see §"range_index no-linear-scan" below).
- **LLR-073.2 `↵` open-in-hex affordance** — each region row ends in `↵`; the
  activation action is UNCHANGED (`RegionRow.Activated` → `OpenInHexRequested`,
  reused, not rewired).
- **LLR-074.1/074.2 region inspector hex peek** — on `RegionRow.Activated`,
  `on_region_row_activated` appends to the existing detail a humanized size, the
  region's dominant band, and a ≤3-row hex peek at the region start
  (`_region_hex_peek` → plain `hexview.render_hex_view`). First peek row address
  == region start (16-aligned starts); a region shorter than 3 rows shows only
  its available rows.
- **LLR-074.3 + MN-4 C-17 (UNCONDITIONAL)** — A2L symbol names still surface in
  the inspector via the batch-43-hardened `build_detail_text` →
  `symbols_in_window` → `symbol_list_text` → `safe_text` path; the peek adds only
  developer-formatted hex (no untrusted text). A bracketed symbol name renders
  verbatim in `#map_detail_body` (asserted, gate sub-assertion).

## 2. Files modified (4)

1. `s19_app/tui/screens_directionb.py` — NEW `MapRuler` widget; NEW module helper
   `_tag_address`; `MemoryMapPanel.__init__` (+`_run_bands`, `+_mem_map`);
   `render_ranges` (+`mem_map` param, store span/run-bands); `_build_band_widgets`
   (+span args, hatch gaps, enriched rows, ruler); NEW `_region_symbol_counts` +
   `_build_region_row` + `_region_hex_peek`; `on_region_row_activated`
   (band + peek). NEW constants `_REGION_MICROBAR_WIDTH`/`_MAP_GAP_HATCH`/
   `_OPEN_IN_HEX_GLYPH`/`_MAP_PEEK_ROWS`; imports `human_bytes`/`microbar`,
   `range_index` primitives, `bisect`.
2. `s19_app/tui/app.py` — `update_memory_map` passes `self.current_file.mem_map`
   as the new trailing `render_ranges` arg (1 line; the peek needs the byte map,
   handed in per the codebase convention — `AbDiffPanel`/`update_hex_view` also
   receive `mem_map` explicitly rather than reaching into the app).
3. `tests/test_tui_map_big.py` — NEW; the 4 black-box ATs (× 2 sizes).
4. `tests/test_tui_snapshot.py` — NEW `_batch47_map_drift_marks` wired into the
   scaffold cells (the 2 map cells drift → xfail(strict=False)).

No frozen file touched (`range_index.py`/`core.py`/`hexview.py`(read-only import)
etc.). `styles.tcss` NOT touched (ruler uses `DEFAULT_CSS`; hatch reuses the
existing `.map-band-seg` rule).

## 3. How to test

```bash
python -m pytest -q tests/test_tui_map_big.py          # the 4 ATs × 2 sizes
python -m pytest -q tests/test_tui_directionb.py       # C-26 census (map/region)
python -m pytest -q tests/test_engine_unchanged.py \
  tests/test_tui_directionb.py -k "tc031 or tc032"     # C-27 dual-guard
python -m pytest -q "tests/test_tui_snapshot.py::test_tc016s_density_layout_snapshot" -k map -rx
ruff check s19_app/tui/screens_directionb.py s19_app/tui/app.py tests/test_tui_map_big.py
```

## 4. Test results (one run each — C-19)

- `tests/test_tui_map_big.py` → **8 passed** (AT-072a/072b/073/074 × {80×24, 120×30}).
- **RED→GREEN**: stashing the two production files and running the new ATs against
  pre-impl code → **8 failed** (no ruler / no `╱` / no `N sym` / inspector shows
  only `_DETAIL_HINT`); restoring → **8 passed**. Captured this session.
- `tests/test_tui_directionb.py` → **174 passed** (C-26 census — all pre-existing
  MemoryMapPanel/RegionRow/band/detail tests still green, **zero test edits**).
- C-27 dual-guard: `test_engine_unchanged.py` (test_tc027) + `test_tc031_*` (×2) +
  `test_tc032_*` (×3) → **6 passed** (0 frozen diff).
- `tests/test_tui_app.py` → **61 passed, 1 xfailed** (pre-existing) — confirms the
  app-level `update_memory_map` mem_map-arg change.
- Snapshot map cells → **2 xfailed** (`map-comfortable-80x24`, `-120x30`; drift
  confirmed + marked, C-22).
- Full collection → **1461 tests collected** (no import/signature breakage).
- `ruff check` (4 changed files) → **All checks passed**.

## 5. Risks

- **Snapshot drift** (2 map cells) rides `xfail(strict=False)` until the batch-47
  canonical-CI regen (Inc-8) — never regenerated locally (`reference_snapshot_regen_env`).
- **`self._mem_map` reference** is stored (not copied) and read-only in the peek —
  no O(N) copy of 40M+ images; `row_bases` supplied so only ≤3 rows materialise.
- **Ruler visual alignment**: at 120×30 the band bar is only 23 cols (glance
  beside it) while the ruler spans the full 52-col grid, so ticks are not
  pixel-aligned under the narrow bar. Acceptable — the ruler describes the image
  address span, and AT-072b asserts the structural invariant (5 ticks + endpoint
  values), not pixel alignment.

## 6. Pending items

- Canonical-CI SVG baseline regen for the 2 map cells (Inc-8 theme+regen follow-up).
- None blocking; no scope drift; no new dependency.

## 7. Suggested next task

Inc-7 (US-FND theme finalize, if not already landed) / Inc-8 canonical-CI
snapshot regen follow-up PR retiring the batch-47 `_batch47_*_drift_marks`.

---

## C-29 two-axis geometry — MEASURED budget → decisions (batch-46 origin control)

Pilot-measured the REAL boxed containers via `App.run_test` (read `region`), both
axes, both regimes, with a 2-band gapped image loaded (NOT the prototype's
full-screen budget):

| container | 80×24 (w × h) | 120×30 (w × h) |
|---|---|---|
| `#map_grid` | 66 × 14 | 52 × 12 |
| `.map-band-bar` | 66 × 1 | **23 × 1** (glance docked beside) |
| `.map-region-list` | 66 × 2 | 52 × 2 |
| region row | 66 × 1 | **52 × 1** |
| `#map_detail` | 66 × 1 (below fold, y=25) | **36 × 2** |

Decisions driven by the measurement:

- **Ruler labels** — the tightest strip is the **52-col grid @120×30** (the band
  bar itself is only 23 cols; the ruler is mounted as a full-width `#map_grid`
  child, so it gets 52/66 cols). Five `0x`-prefixed labels (5×10 = 50 chars)
  leave only 2 cols for 4 gaps → overlap. **C-13.1 deficit-matched fallback**:
  drop the `0x` prefix (label-trim recovers 2 cols/label = 10 cols) → 8-digit
  labels (5×8 = 40) fit 52 with `width: 1fr` distribution and no overlap.
  Asserted structurally (exactly 5 ticks + endpoint values), never a col count.
- **Hex-peek rows** — `#map_detail` is `height: auto` and the detail Static
  already overflows-under-scroll by the batch-45 design (build_detail_text emits
  ~7 lines into a 2-row visible pane @120×30). The peek is CONTENT reachable
  under scroll, never clipped → kept the LLR-074.2 target of **3 rows** (region
  shorter than 3 rows shows only its available rows).
- **Region-row count** — `.map-region-list` is `height: auto`; all rows render
  and overflow is reachable under scroll (LLR-073.3 satisfied — not clipped). No
  row count asserted.

## range_index — how `N sym` avoids the linear scan (LLR-073.1)

`_region_symbol_counts` builds ONE `build_sorted_range_index` over ALL region
ranges (O(R log R)), then makes a SINGLE pass over the tags: each address is
tested with `address_in_sorted_ranges` (O(log R)) and, on a hit, located to its
owning region by the same `bisect.bisect_right(starts, addr)` the primitive uses
internally — O(T log R) total. No per-region re-scan; no O(tags × regions) nested
loop. AT-073 asserts each row's shown `N sym` equals an INDEPENDENT
`build_sorted_range_index([(start,end)])` + `address_in_sorted_ranges` count.

## C-17 inspector sub-assertion (MN-4, UNCONDITIONAL)

AT-074 seeds `sensor[red]` as an A2L symbol overlapping the activated non-first
region and asserts it renders verbatim in `#map_detail_body`. The name flows
through the batch-43-hardened `symbol_list_text` → `safe_text` (= `Text(value)`,
never `Text.from_markup`) — no markup parse, no `MarkupError`, no crash. The peek
adds only developer hex (no untrusted text). Green at both sizes.

## C-22 snapshot-drift list (per-cell)

Exactly **2 cells** drift, both marked `xfail(strict=False)` via
`_batch47_map_drift_marks`:
- `map-comfortable-80x24` — band strip hatch + span-proportional layout + ruler +
  enriched region rows.
- `map-comfortable-120x30` — same.

Reason per-cell: only the map scaffold cells render the map body with a file
loaded; the inspector hex peek shows only on activation (snapshot captures the
un-activated `_DETAIL_HINT`), so it does not drift the baseline. **C-28**: no
App-level `Binding`/footer/header/rail change this increment → no shared-chrome
drift on other screens (verified: the 2 mismatches are the map cells only).

## C-26 reverse-census (MemoryMapPanel 23 + RegionRow 9 — §6.5 Amendment B)

Reverse-grepped `MemoryMapPanel` / `RegionRow` / `_build_band_widgets` /
`render_ranges` / `on_region_row_activated` / `#map_detail_body` / `#map_grid` /
`.map-region-row` / `.map-band-seg` / `build_detail_text` across `tests/`. The
32-test map/region surface lives entirely in `tests/test_tui_directionb.py`
(non-frozen). **Outcome: 0 test edits needed — all 174 pass.** Why the enriched
render did not break the OLD assertions:

- **Region-row text** (`test_at069/at070/at071/at071b`, `test_at_r3_region_click`)
  — `human_bytes(256)` == `"256 B"` and `human_bytes(512)` == `"512 B"` (both
  < 1024), so the `f"{run_bytes} B"` / `"256 B"` / no-`"512 B"` substrings still
  hold; the new `microbar` uses `█`/`░` (never `▓`), so `"▓" not in const_text`
  still holds; `0x{start}` / band label / glyph are all preserved.
- **Band bar** (`test_at035`) — the hatch segment carries `map-band-gap` (does NOT
  start with `band-`), so the `band_tokens` filter still counts ≥2 real bands;
  the query returns all segment widgets regardless of visible clipping.
- **Inspector** (`test_tc041_6`, `test_tc062_1`, `test_at074_single_click`,
  `test_b01`, `test_at_r3_region_click_detail`) — the appended band/peek lines are
  ADDITIVE; the OLD substrings (`evil[red]`, `0x80000000`, `256 bytes`, exact
  region line, OpenInHexRequested count == 1) are unchanged.
- **Geometry** (`test_at073b`, `test_tc041_10`) — the ruler is a separate grid
  row; band-bar/glance widths and the reflow class are untouched.

## C-27 result

Frozen src (`test_tc027`/`test_tc031_*`) + frozen tests (`test_tc032_*`) → **6
passed, 0 diff**. `range_index.py` used read-only; `hexview.render_hex_view`
imported read-only; no new test in a frozen file.

## Evidence checklist

- [x] Tests/type checks/lint pass — 8 map_big + 174 directionb + 61 app + 6 C-27
  guards + ruff clean (evidence §4, one run each).
- [x] No secrets in code or output — public `examples/` fixtures + synthetic
  builders only; injection payload is synthetic (`sensor[red]`).
- [x] No destructive commands — only `git stash push/pop` of 2 files for the RED
  check, restored (stash dropped).
- [x] File count within cap — 4 files (≤5); app.py added for the mem_map hand-in
  (peek needs the byte map, per the codebase's hand-in convention).
- [x] Review packet attached — this file.

### Gate outcome (orchestrator, 2026-07-15)
- **Independent code-review:** APPROVE-WITH-NITS, 0 HIGH / 0 MEDIUM. Both focus areas verified CLEAN: F1 N-sym region assignment correct at every boundary (start-inclusive, end-exclusive half-open, gap-tag not counted) with a genuine independent per-row oracle in AT-073; F2 inspector C-17-safe (safe_text path, AT-074 plants `sensor[red]` at a non-first region, verbatim, no MarkupError) + bounds-safe (≤3 rows, empty-map short-circuit, no OOB). Reproduced: map-big 8/8, C-27 guards green, MemoryMapPanel/RegionRow slice 26 passed. C-13.1 ruler 0x-drop fallback sound; app.py 1-line deviation back-compat (default arg, both callers verified); MapRuler no shadowing + self-CSS (no theme leak); 2-cell drift, C-28 clean.
- **F3 (LOW) FIXED:** hex-peek docstring falsely claimed "all S19 region starts are 16-aligned" — corrected to describe the standard hex-grid convention (first row = the HEX_WIDTH-aligned row containing `start`; equals region start when 16-aligned). Behavior unchanged (sound + conventional); docstring-only. Ruff clean, import OK.
- **Gate axis check:** Coverage OK (AT-072a/072b/073/074 realized single-node both regimes; C-17 MN-4 sub-assertion); Certainty OK (N-sym genuine oracle, C-17 live-path counterfactual, C-29 both-axes MEASURED → geometry decisions justified not assumed); Evidence OK (reproduced counts + boundary trace). **APPROVE.** → Inc-7 (classed hex, LLR-066.3).
