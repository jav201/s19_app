# 01 — Requirements — 2026-07-06-batch-27 — R-TUI-041 Interactive Memory-Map Minimap

> **Batch objective:** Redesign the TUI "Memory Map" rail screen from a read-only monochrome per-range text list (`MemoryMapPanel.render_ranges`, `screens_directionb.py:192`) into an interactive, colour-coded spatial minimap ("Variant B v2", operator-approved via prototype). Three stories: US-035 (colour-coded spatial minimap grid), US-036 (cell selection → detail pane), US-037 (coverage stats strip).
>
> Language: **en** · Flow: `/dev-flow` · New requirement **R-TUI-041** (supersedes/extends the read-only **R-TUI-026**, `REQUIREMENTS.md:549-556`). Highest existing id before this batch = R-TUI-040.
>
> **Normative convention:** `shall` only inside HLR/LLR statements. `should`/`may` never appear as a modal inside a requirement statement.

---

## 1. Introduction

### 1.2 Scope
**In scope (TUI-side only):** respecify `MemoryMapPanel` and its wiring in `screens_directionb.py`, `app.py` (`_compose_screen_map` at `app.py:1322`, `update_memory_map` at `app.py:7180`), and `styles.tcss` (`#map_content`/`#memory_map_panel` at `styles.tcss:511-527`). The panel gains a 2-D colour-coded cell grid, a cell-detail pane, and a coverage stats strip, all driven on the UI thread from the already-computed `LoadedFile` snapshot and the already-computed `ValidationReport`.

**Out of scope / HARD constraints:** NO edits to the engine-frozen set (`core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — frozen set confirmed at `tests/test_engine_unchanged.py` `_ENGINE_PATHS` + TC-031). The panel performs NO new coverage/parse/analysis — it reads `LoadedFile.ranges`, `LoadedFile.range_validity`, and the pre-computed `ValidationReport.issues` verbatim. All severity colours route through `css_class_for_severity` (`color_policy.py:17`, frozen → consumed read-only, never re-implemented).

### 1.3 Definitions
| Term | Definition |
|------|------------|
| Cell / address window | One tile of the grid = a contiguous half-open address span `[cell_start, cell_end)`. Cell size auto-scales so the whole image span fits the visible grid (design decision 1). |
| Image span | `[min(start over ranges), max(end over ranges))` — the same `span_start`/`span_end` arithmetic already in `render_ranges` (`screens_directionb.py:237-239`). |
| Cell status | `valid` (green) / `invalid` (red) / `gap` (grey), derived from the ranges/validity that overlap the cell. |
| Cell-scoped issue | A `ValidationIssue` whose `address` (`validation/model.py:126`) is in `[cell_start, cell_end)`. |
| Wide / narrow regime | `width >= 120` / `width < 120`, the existing breakpoint toggled by `_apply_width_regime` (`app.py:3946`) via the `width-narrow` class. |

---

## 2. Overall description

### 2.1 Product perspective
The Memory Map is one of the 8 Direction-B rail screens (`#screen_map`, `_compose_screen_map` at `app.py:1322`). Today it mounts a single scrollable `MemoryMapPanel` (`Static`, `markup=False`, `screens_directionb.py:145,187`) whose `render_ranges(ranges, range_validity)` (`screens_directionb.py:192`) prints one text line per range + gap with a `#`-fill bar (`_BAR_WIDTH=40`, `screens_directionb.py:183`). It is driven once per load by `update_memory_map` (`app.py:7180`), which passes `current_file.ranges` + `current_file.range_validity` straight through (`app.py:7211-7214`). This batch replaces the text body with an interactive spatial grid + detail pane + stats strip while preserving the render-only contract.

### 2.4 Constraints
- **Render-only:** the panel is driven exclusively by `update_memory_map` on the UI thread. It does no parsing/coverage/analysis — verbatim consumption of `LoadedFile` fields + `ValidationReport.issues` (LLR-041.7).
- **Colour source of truth:** `css_class_for_severity` / `SEVERITY_CLASS_MAP` (`color_policy.py:5-19`); no hard-coded hex/style for severity (LLR-041.3). Cell status→class uses the existing `sev-*` CSS classes (`sev-ok`, `sev-error`, `sev-neutral`).
- **Engine-frozen:** no diff vs `main` on any frozen path (census in probe ledger P-11).
- **Reflow mechanism:** reuse the existing `width-narrow` class + `on_resize`/`_apply_width_regime` (`app.py:3946-3956`); do NOT invent a second breakpoint (LLR-041.10).

### 2.5 Assumptions and dependencies
- `LoadedFile.ranges: List[Tuple[int,int]]` (end-exclusive) and `LoadedFile.range_validity: List[bool]` positionally aligned — **verified** `models.py:46-47`, docstring "`end` exclusive" `screens_directionb.py:207-210`.
- `ValidationIssue` fields the detail pane reads: `code: str`, `severity: ValidationSeverity`, `message: str`, `symbol: Optional[str]`, `address: Optional[int]` — **verified** `validation/model.py:121-129`. `address` is `Optional` — issues with `address is None` cannot be cell-anchored (drives the boundary catalog + open decision R-1).
- `S19TuiApp._validation_issues: list[ValidationIssue]` holds the already-computed issues at render time — **verified** declared `app.py:764`, populated `app.py:6295-6296, 6602-6603`, cleared `app.py:6090-6091, 7716-7717`. `_validation_report: Optional[ValidationReport]` at `app.py:763`. `ValidationReport(issues, coverage)` — **verified** `validation/engine.py:15-18`.
- `CoverageMetrics` exists but is A2L/MAC-cross-oriented (`mac_in_s19`, `a2l_in_s19` — `validation/model.py:168-173`); it does **NOT** carry S19 byte-coverage %, gap count, or largest gap. The stats strip (US-037) derives its numbers by the SAME arithmetic already in `render_ranges` (covered bytes `screens_directionb.py:240`, gap spans `:249-250`, span `:237-239`) — display arithmetic on already-parsed addresses, not new analysis (render-only contract preserved).

### 2.6 Source user stories

| ID | User Story | Source | DoR status |
|----|------------|--------|------------|
| US-035 | As an operator inspecting a loaded image, I want the Memory Map screen to show a colour-coded 2-D spatial minimap where each cell is an address window coloured valid/invalid/gap, so that I can see the whole image's coverage shape at a glance instead of reading a monochrome per-range list. | operator prototype approval ("Variant B v2") | READY |
| US-036 | As an operator, I want to select a cell (by click or keyboard navigation) and see a detail pane with the cell's status, address window, the covering region, the validation issues anchored in that cell, and an "Open in Hex View" jump, so that I can drill from the spatial overview to the exact bytes and findings. | operator prototype approval | READY |
| US-037 | As an operator, I want a coverage stats strip (coverage %, bytes covered, valid/invalid range counts, gap count + largest gap, total issues), so that I get the quantitative summary alongside the spatial view. | operator prototype approval | READY |

Decisions confirmed at the Phase-0 DoR gate (2026-07-06): (1) cell size AUTO-SCALES to fit the grid; (2) detail pane fixed-right ≥120 cols, reflows below the grid <120 cols; (3) issue anchoring CELL-SCOPED + region-issue count.

---

## 3. High-level requirements (HLR)

### HLR-035 — Colour-coded spatial minimap grid
- **Traceability:** US-035
- **Statement:** When a file is loaded and the Memory Map screen is rendered, the system shall display the image's memory span as a 2-D grid of address-window cells in which each cell is coloured `valid`/`invalid`/`gap` from `LoadedFile.ranges` and `LoadedFile.range_validity`, sized so the whole image span fits the visible grid.
- **Validation:** `test (pilot)` + `inspection`
- **Numeric pass threshold:** grid contains ≥1 `sev-ok` cell AND ≥1 `sev-error` cell for `case_04`; ≥1 grey/`sev-neutral` gap cell for `case_02`; header shows an "≈ N KiB/cell" label; 0 frozen-path diffs.
- **Priority:** high
- **Acceptance (black-box):** observable outcome = a colour grid (green/red/grey) representing the whole image, with a per-cell size label; shipped surface = `#screen_map` → `MemoryMapPanel` driven by `update_memory_map`; observation = Pilot reads cell CSS classes + header label. **AT:** AT-035.
- **Boundary catalog (QC-3):** ☑ empty (no file → neutral empty state, LLR-041.9) · ☑ boundary (single range, no gaps → all-green) · ☑ invalid (`case_04` → red cells) · ☑ error (all-gap / zero-span guard → no divide-by-zero, LLR-041.2).

### HLR-036 — Cell selection → detail pane
- **Traceability:** US-036
- **Statement:** When the operator selects a cell (pointer click or keyboard navigation), the system shall display, for that cell, a status chip, its address window `[cell_start, cell_end)`, the covering region (name/bounds/size/status or "gap"), the `ValidationReport` issues whose address is in that cell plus a one-line "N issues in region" count, and an "Open in Hex View" action that drives `update_hex_view(focus_address=cell_start)`.
- **Validation:** `test (pilot)`
- **Numeric pass threshold:** after selecting a non-default cell, the detail pane's rendered window text equals that cell's `[start,end)`; for a cell overlapping an invalid range the status chip routes through `css_class_for_severity(ValidationSeverity.ERROR)` = `"sev-error"`; Open-in-Hex results in `update_hex_view` called with `focus_address == cell_start`.
- **Priority:** high
- **Acceptance (black-box):** observable outcome = detail content changes to the selected cell; a jump focuses the hex view; shipped surface = `MemoryMapPanel` detail sub-widget + existing `update_hex_view`; observation = rendered detail text + hex-view render after jump. **ATs:** AT-036a (non-default cell → detail changed, C-10), AT-036b (Open-in-Hex focuses `cell_start`), AT-036c/d/e (valid/invalid/gap branch content, C-10(b)).
- **Boundary catalog (QC-3):** ☑ empty (cell 0 issues → empty issue list, region-count line still shown) · ☑ boundary (default cell 0 vs a non-default cell — AT drives non-default) · ☑ invalid (cell over invalid range → red chip + issue code+addr) · ☑ error (gap cell → "gap", no crash; `address is None` issue excluded, LLR-041.5).

### HLR-037 — Coverage stats strip
- **Traceability:** US-037
- **Statement:** While a file is loaded, the system shall display a coverage stats strip on the Memory Map screen showing coverage %, bytes covered, valid-range count, invalid-range count, gap count, largest-gap bytes, and total validation-issue count, all derived from `LoadedFile.ranges`/`range_validity` and `len(_validation_issues)`.
- **Validation:** `test (pilot)` + `analysis`
- **Numeric pass threshold:** coverage % strictly < 100 for `case_02`; gap count ≥ 1; largest-gap value == max inter-range span from the fixture; total-issue count == `len(app._validation_issues)`.
- **Priority:** medium
- **Acceptance (black-box):** observable outcome = a strip with the seven statistics matching the fixture's true coverage; shipped surface = `MemoryMapPanel` stats sub-widget; observation = Pilot asserts numeric substrings. **AT:** AT-037.
- **Boundary catalog (QC-3):** ☑ empty (no file → strip absent/neutral) · ☑ boundary (single range → 100%, gap 0, largest-gap 0) · ☑ invalid (`case_04` → invalid count ≥ 1) · ☑ error (zero-span guard → no divide-by-zero).

---

## 4. Low-level requirements (LLR)

### LLR-041.1 — Cell status derivation (grid model)
- **Traceability:** HLR-035
- **Statement:** The `MemoryMapPanel` shall map each grid cell `[cell_start, cell_end)` to `valid`/`invalid`/`gap` by testing overlap against the sorted `ranges`/`range_validity`: a cell overlapping only valid range(s) → `valid`; overlapping any invalid range → `invalid`; overlapping no range → `gap`.
- **Validation:** `test (unit)` — TC-041.1. Pure function of `ranges`/`range_validity`; membership via `range_index` (consumed read-only) or a local overlap test (**NEW helper on the panel, created in Phase 3**).

### LLR-041.2 — Auto-scale cell size (layout arithmetic)
- **Traceability:** HLR-035
- **Statement:** The panel shall choose a cell size (bytes-per-cell) such that `ceil(image_span / bytes_per_cell)` cells fit the visible grid area (columns × rows of `#memory_map_panel`), render an "≈ N KiB/cell" header label, and when `image_span <= 0` show the neutral empty state and compute no ratio (no divide-by-zero).
- **Validation:** `analysis` + `test (unit)` — TC-041.2. Grid capacity is **`assumed — measure in Phase 3`** via `App.run_test(size=(80,24))`/`(120,30)` reading `panel.size`; zero/one-range guards mirror the existing `total_span <= 0` guard (`screens_directionb.py:288`). **Determinism note (qa R-4):** cell count must be a pure function of `(span, measured grid geometry)`, not runtime layout drift, so the snapshot is stable.

### LLR-041.3 — Cell colours route through the frozen severity map
- **Traceability:** HLR-035, HLR-036
- **Statement:** The panel shall colour cells and the detail status chip only via the `sev-*` CSS classes obtained from `css_class_for_severity` (`invalid`→`ERROR`=`"sev-error"`; `valid`→`OK`=`"sev-ok"`; `gap`→`NEUTRAL`=`"sev-neutral"`), and shall not hard-code any severity hex value or inline style.
- **Validation:** `inspection` + `test (unit)` — TC-041.3. `rg` expects 0 severity hex literals in the panel; unit test asserts an invalid cell carries `sev-error` (== `SEVERITY_CLASS_MAP[ValidationSeverity.ERROR]`, `color_policy.py:6`). `color_policy.py` frozen, consumed only.

### LLR-041.4 — Cell selection updates the detail pane
- **Traceability:** HLR-036
- **Statement:** When a cell is selected (click or keyboard focus/`Enter`), the panel shall render into the detail pane: a status chip (LLR-041.3 class), the cell window `0x{start:08X}-0x{end-1:08X}`, the covering region (`name`/bounds/`size`/status, or "gap — no region"), the cell-scoped issue list (LLR-041.5), and the region-issue count line.
- **Validation:** `test (pilot)` — TC-041.4 / AT-036a. Selection handler + detail-render method are **NEW — created in Phase 3**. Covering-region "name" for a bare S19 range = its `0x..-0x..` bounds; A2L-symbol naming of regions is **out of scope for this batch (deferred, see R-3)** — no modal.

### LLR-041.5 — Cell-scoped issue anchoring (read-only join, no new analysis)
- **Traceability:** HLR-036
- **Statement:** The panel shall populate the detail pane's primary issue list with exactly those `_validation_issues` whose `address` is an int in `[cell_start, cell_end)`, and additionally show a one-line "N issues in region" count = issues whose address falls in the covering range; issues with `address is None` shall be excluded from the cell list (cannot be spatially anchored).
- **Validation:** `test (unit)` + `test (pilot)` — TC-041.5 / AT-036d. Boundary + negative: in-window included, `window_end` excluded, `address is None` excluded. Reads `ValidationIssue.address/.code/.severity/.message/.symbol` (`validation/model.py:121-129`). Source list = `S19TuiApp._validation_issues` handed to the panel by `update_memory_map` (**the only app.py call-site change**, extends `app.py:7211-7214`).

### LLR-041.6 — Open-in-Hex drives the existing focus path
- **Traceability:** HLR-036
- **Statement:** When the operator triggers "Open in Hex View" from the detail pane, the app shall call the existing `update_hex_view(focus_address=cell_start)`; the panel shall not implement its own hex rendering.
- **Validation:** `test (pilot)` — TC-041.6 / AT-036b. `update_hex_view(focus_address: Optional[int])` verified `app.py:7219`; focus math `app.py:7229-7235`. Jump wired app-side (panel message/callback → `update_hex_view`), keeping the panel render-only.

### LLR-041.7 — Render-only / no new analysis constraint (explicit)
- **Traceability:** HLR-035, HLR-036, HLR-037
- **Statement:** `MemoryMapPanel` shall perform no parsing, coverage computation, validation, or file I/O; it shall consume only the arguments handed to it by `update_memory_map` (`ranges`, `range_validity`, and the pre-computed issue list) and derive cells/stats by arithmetic on those already-parsed values.
- **Validation:** `inspection` — TC-041.7. `rg -n 'open\(|Path\(|parse_|validate_|build_loaded|read_text|load\('` scoped to the `MemoryMapPanel` class body → expect 0 hits. Preserves the existing docstring contract (`screens_directionb.py:154-155`).

### LLR-041.8 — Coverage stats derivation (arithmetic on parsed addresses)
- **Traceability:** HLR-037
- **Statement:** The stats strip shall compute coverage % = `covered_bytes / image_span * 100`, bytes covered = `Σ(end-start)`, valid/invalid counts from `range_validity`, gap count and largest-gap bytes from consecutive-range subtraction, and total issues = `len(_validation_issues)` — with the guarding `image_span > 0` before division.
- **Validation:** `analysis` + `test (unit)` — TC-041.8. Reuses arithmetic already in `render_ranges` (covered `:240`, span `:237-239`, gap `:249-250`). The strip's issue count and the LLR-041.5 detail join both read the **single canonical source `_validation_issues`** (the list passed into `update_memory_map`) — never `_validation_report.coverage`/`.issues` re-derived (arch MINOR-3).

### LLR-041.9 — Empty / no-file state preserved
- **Traceability:** HLR-035, HLR-037
- **Statement:** When `ranges` is empty, the panel shall show a neutral no-file note and render no grid, no detail content, and no stats — preserving `_EMPTY_TEXT` (`screens_directionb.py:184,226-229`) and the `#screen_map` `EmptyStatePanel` (`app.py:1359`).
- **Validation:** `test (pilot)` — TC-041.9.

### LLR-041.10 — Two-regime reflow via the existing `width-narrow` mechanism
- **Traceability:** HLR-035, HLR-036 (layout)
- **Statement:** In the wide regime (`width >= 120`) the panel shall lay the detail pane as a fixed-width right column beside the grid; in the narrow regime (`width < 120`) the panel shall lay the grid full-width with the detail pane in a region below it — driven by the existing `width-narrow` class toggled by `_apply_width_regime`/`on_resize`, with new `#map_content`/`#memory_map_panel` rules in `styles.tcss` (NOT a new breakpoint).
- **Validation:** `test (pilot)` + `inspection` — TC-041.10. Mechanism verified `app.py:3919` (`def _apply_width_regime`, `narrow = width < 120` at `:3946`), `:3954-3956` (`on_resize`), existing narrow rules `styles.tcss:204-216`. **C-13 budget below (computed).**

### LLR-041.11 — Markup-safe rendering of file-derived text (security, B-1)
- **Traceability:** HLR-035, HLR-036 (added Phase-1 iteration 2 — Phase-2 blocker B-1)
- **Statement:** Because the panel renders with Rich markup enabled (`markup=True`, required to colour cells), every file-derived string reaching the grid or detail pane — `ValidationIssue.message`, `ValidationIssue.symbol`, `ValidationIssue.code`, and any covering-region name — shall be rendered markup-safe by composing the content as `rich.text.Text` with explicit `style=` arguments (so the value is treated as literal text), or equivalently by passing each interpolated file-derived value through `rich.markup.escape` before it enters any markup string; the panel shall not interpolate raw file-derived text into a markup-parsed string.
- **Rationale (informative):** a loaded A2L/MAC symbol such as `sensor[red]` or `x[link=file:///…]` would otherwise corrupt the render, inject styling, or raise `rich.errors.MarkupError` crashing the Memory Map screen on load — the tool's core untrusted-input path. `_scrub_issue_message` (`model.py:25-84`) strips ANSI/control chars only (not `[`/`]`) and never touches `.symbol`, and is engine-frozen → the fix is panel-side, not there.
- **Validation:** `test (unit)` + `test (pilot)` — TC-041.11 (unit: a `symbol`/`message` containing `[red]`/`[/]`/`[link=…]` and a raw ANSI byte renders as literal text — no `MarkupError`, no style/ANSI leak) + AT-036f (black-box: seed an issue whose `symbol` contains `[red]`, select its cell → `#map_detail` renders the literal brackets and the screen does not crash).
- **Acceptance criteria:** the `Text`-with-explicit-styles construction is preferred over bare `rich.markup.escape` because it also neutralises raw ANSI bytes in the never-scrubbed `.symbol` (security F2). Fix lives in `screens_directionb.py` (panel-side) — 0 engine-frozen diff. Sources verified: `rules.py:360/362/465/467/476/478/509/511` (file-derived `message=`/`symbol=` sinks); `model.py:137` (scrubs only `.message`).

---

## 5. Validation strategy

### 5.1 Methods
**Layer A (white-box `TC-NNN`):** unit tests for cell-status/stats/issue-filter math (LLR-041.1/.2/.5/.8), inspection for render-only + colour-routing (LLR-041.3/.7/.10), analysis for coverage arithmetic (LLR-041.8). **Layer B (black-box `AT-NNN`):** Textual Pilot over the real `#screen_map` with `case_04_bad_checksums` / `case_02_gaps_and_patch_targets`.

### 5.2 Dual-traceability

**Behavioral chain (black-box):**

| US | Observable outcome | Shipped surface | Acceptance test | Observed? |
|----|--------------------|-----------------|-----------------|-----------|
| US-035 | Green/red/grey cell grid + "≈ N KiB/cell" header over `case_04`/`case_02` | `#screen_map` → `MemoryMapPanel` | AT-035 | Phase 4 |
| US-036 | Non-default cell → detail changes; per-kind content; Open-in-Hex focuses `cell_start`; markup-safe file text | `MemoryMapPanel` detail + `update_hex_view` | AT-036a/b/c/d/e/f | Phase 4 |
| US-037 | Stats strip matches fixture's true coverage | `MemoryMapPanel` stats strip | AT-037 | Phase 4 |

**Functional chain (white-box):** HLR-035→TC-035a/b; HLR-036→TC-036a/b; HLR-037→TC-037; LLR-041.1→TC-041.1 … LLR-041.11→TC-041.11 (one TC per LLR).

> **Provisional-identifier note (V-5):** all `AT-NNN`/`TC-NNN` ids, the test file (`tests/test_tui_directionb.py`, per `REQUIREMENTS.md:555`), and `-k` selectors are provisional-until-Phase-3, reconciled at Phase 4.

### 5.3 Batch acceptance criteria
- Every LLR-041.x covered by ≥1 passing TC; every US ≥1 passing AT through `#screen_map` with boundary + negative evidence.
- AT-036a drives a NON-DEFAULT cell (C-10) and asserts detail changed; AT-036c/d/e assert per-branch content (valid name / invalid code+addr / gap "uncovered"); AT-036f asserts markup-safe rendering of a bracket-bearing file symbol (no crash, literal brackets).
- 0 diffs on any engine-frozen path; 0 hard-coded severity colours in the panel; 0 raw file-derived text interpolated into a markup-parsed string (LLR-041.11).
- Full suite green (≥ current count; `test_engine_unchanged` + TC-031 pass).

---

## 6. Appendices

### 6.2 C-13 geometry-budget arithmetic (detail-pane reflow) — COMPUTED, not assumed

**Container facts (verified):** `#screen_map` is a `.db-screen` filling `#workspace_body` (`.db-screen { width:100% }` `styles.tcss:137-140`). `#workspace_body { width:1fr }` (`styles.tcss:131`) inside `#workspace_shell { layout:horizontal }` (`:120-122`), whose other child is `#rail_slot`/`#activity_rail`. **Rail = 22 cols wide (`#activity_rail { width:22 }` `:941`), 4 cols narrow (`.width-narrow #activity_rail { width:4 }` `:977-980`).** So `body_w = terminal_cols − rail_w`.

**Wide regime (terminal = 120, `width-narrow` OFF):** `body_w = 120 − 22 = 98`. Detail pane = fixed **36 cols**; grid gets the `1fr` remainder = `98 − 36 = 62 > 0` → **NO overflow.** The map screen has only ONE fixed sibling (the detail column) inside a `1fr` body — unlike the Workspace 3-pane failure (TWO fixed side panes 22+82+40 summing past the body). Here the grid is elastic and absorbs the remainder. After ~6 cols border/padding chrome (`#map_content` round border + `#memory_map_panel padding:1 2`), `62 − 6 ≈ 56 ≥ 20` (usable-grid floor) → comfortable.

**Narrow regime (terminal < 120, rail = 4):** `body_w = terminal − 4`; worst supported 80 cols → `76`. Grid full-width, detail **below** (vertical stack) → no horizontal fixed-sibling contention; vertical overflow scrolls (`#map_content` is a `ScrollableContainer`, `app.py:1355`).

**Conclusion:** wide regime positive-budget (62-col grid beside 36-col detail in a 98-col body); narrow stacks. Workspace overflow NOT repeated. Exact post-chrome widths flagged **`assumed — measure in Phase 3`** via `App.run_test(size=(120,30))`/`(100,30)`/`(80,24)` reading `query_one("#memory_map_panel").size`.

### 6.3 Open risks / decisions for the gate
- **R-1 (address-less issues — OPEN DECISION, low-risk):** issues with `address is None` (allowed, `validation/model.py:126`) cannot be cell-anchored. In-spec default (LLR-041.5): excluded from the cell list; surfaced only via the region-count line if their address falls in the range; a fully address-less issue appears in neither. **Operator confirmation requested:** is the region-count line sufficient, or should address-less issues get a screen-level banner? Default = region-count line only.
- **R-2 (issue-address density — HIGH, testability):** a lone `case_04` S19 load may surface the bad checksum as a per-line/per-file error WITHOUT a populated `address` (rules populate `address=` mainly on cross-artifact rules, `validation/rules.py:119,384`). The invalid-cell AT (AT-036d) therefore installs the full triple to force address-anchored issues, OR seeds `app._validation_issues` with an explicit `ValidationIssue(code=…, severity=ERROR, address=<in an invalid cell>)` before `update_memory_map()` — still black-box on the render surface. Confirm the fixture path with the dev at Phase 2/3.
- **R-3 (covering-region name):** a bare S19 range has no human name → detail pane uses its `0x..-0x..` bounds as the "name". A2L-symbol naming deferred.
- **R-4 (auto-scale snapshot determinism):** cell count must be a pure function of `(span, measured geometry)` not runtime layout, else the 120×30 snapshot flaps. Covered by TC-041.2.
- **R-5 (Textual grid cost):** many small cell widgets could be render-heavy; capped to measured capacity (whole image fits) → bounded widget count. Phase-2 perf sanity if capacity × redraw is large.

### 6.4 Phase-1 reconciliation log
R-TUI-041 supersedes the read-only clause of R-TUI-026 (`REQUIREMENTS.md:549-551`): the "without computing new coverage data" constraint is **retained and strengthened** (LLR-041.7); the "monochrome text list" realisation is **replaced** by the interactive grid. R-TUI-026's LLR-012.1 render-only contract preserved verbatim as LLR-041.7 (no contradiction). REQUIREMENTS.md body edit for R-TUI-041 lands in Phase 3/6.

### 6.5 Requirement amendments (Phase-1 iteration 2 — from Phase-2 blocker + majors)
Triggered by the Phase-2 cross-review (`02-review.md`): 1 blocker (B-1 markup injection) + 4 majors. `iterate-to-refine` (operator-approved 2026-07-06). Design unchanged; edits are additive/clarifying.

- **NEW — LLR-041.11 (markup-safe rendering)** + TC-041.11 + AT-036f. **Before:** no requirement addressed the `markup=False→True` flip; file-derived `.message`/`.symbol`/`.code`/region name would reach a markup-parsed render unescaped. **After:** LLR-041.11 mandates `rich.text.Text` with explicit styles (or `rich.markup.escape`), panel-side, 0 frozen diff. Parent HLR re-read: HLR-035/036 acceptance now include markup-safe rendering; no contradiction. Resolves security F1 (blocker) + F2 (`.symbol` ANSI, folded via the `Text` approach).
- **REWORD — LLR-041.4.** **Before:** "…(A2L-symbol naming deferred, `may`)." **After:** "…A2L-symbol naming of regions is out of scope for this batch (deferred, see R-3) — no modal." Removes the only stray modal (arch MAJOR-2). No threshold change.
- **PIN — AT-036d.** **Before:** two mitigation paths ("install full triple OR seed `_validation_issues`"). **After:** pinned to the deterministic seed-issue path only; full-triple alternative deleted (qa M-1). No requirement statement change (test-authoring precision).
- **NEW — `map-comfortable-80x24` snapshot cell** (qa M-2) added to the §7 snapshot plan to lock the narrow reflow; xfail-until-baseline.
- **NEW — AT-036g** (address-less negative, qa m-5) locking the R-1 default; **clarified** LLR-041.8 canonical stats source (arch MINOR-3); **TC-041.2** version-stable capacity (qa m-6); **TC-041.8** exact literals in Phase 3 (qa m-3); **AT-036b** behavioral hex assertion note (qa m-4); citation `app.py:3919` def aligned (arch MINOR-1).

**Re-derived nodes:** +LLR-041.11, +TC-041.11, +AT-036f, +AT-036g. Traceability §5.2 updated (US-036 → AT-036a/b/c/d/e/f; functional chain → LLR-041.11→TC-041.11). No LLR deleted.

---

## 7. Validation execution detail (qa-reviewer) — AT/TC/snapshot specs

**Pilot idiom (verified):** construct `S19TuiApp(base_dir=tmp_path)`, `async with app.run_test(size=(W,H)) as pilot`, install fixture, `app.action_show_screen("map")`, `await pilot.pause()`, query widgets by id, assert on rendered text. Source: `test_tui_directionb.py:2908-2916`, `:2986-3000`; nav `:2991`. Fixture-install helper `_install_case_02_loaded_file` (`:2876-2889`); add sibling `_install_case_04_loaded_file`. For issue-anchored cases, populate `app._validation_issues` (via `build_validation_report(...)` or the full-triple load path `_apply_prepared_load`, `app.py:6295-6296`) before `update_memory_map()`.

**Acceptance tests (black-box; each RED on the current text-list panel — no `#map_grid`/`#map_detail`/`#map_stats`/Open control exists today, `app.py:1353-1362`):**

- **AT-035** (US-035, fixture `case_02`): show `map`; assert grid has ≥1 `.map-cell` with a valid class + ≥1 gap class; header matches `≈\s*[\d.]+\s*KiB/cell`. RED: `query("#map_grid")`/`.map-cell` → NoMatches.
- **AT-036a** (US-036, C-10 non-default, `case_02`): capture default detail text; keyboard-nav to a different cell (`pilot.press("right"); ...; "enter"`); assert `second != first` AND `second` contains the new cell's start-address token. RED: no `#map_detail` → NoMatches.
- **AT-036b** (US-036 Open-in-Hex, `case_02`): select a valid cell at start `A`; trigger Open-in-Hex; assert `#screen_map` hidden / hex screen visible AND the hex row containing `A` renders (confirms `update_hex_view(focus_address=A)`). RED: no Open control → NoMatches.
- **AT-036c** (valid branch, `case_02`): select a cell inside a valid range; assert status chip valid + covering region bounds/size + region label. RED: NoMatches.
- **AT-036d** (invalid branch — **PINNED to the deterministic seed-issue path**, qa M-1): because both `address=` sites in `rules.py` (`:119/:384`) are MAC-only, a lone `case_04` S19 load yields no address-anchored issue. So: load `case_02`/`case_04`, then set `app._validation_issues = [ValidationIssue(code="S19_RECORD_CHECKSUM", severity=ValidationSeverity.ERROR, message=…, address=<an address inside a known invalid cell>)]`, call the shipped `update_memory_map()`, `await pilot.pause()`, select that cell; assert invalid chip + the issue `code` + `0x{address:08X}` + "N issue(s) in this cell" + "N issues in region". Still black-box (drives the shipped surface, observes `#map_detail`). The full-triple alternative is dropped. RED: NoMatches.
- **AT-036e** (gap branch, `case_02`): select a cell in a gap; assert "uncovered"/"gap" chip + gap window; must NOT claim a covering region. RED: NoMatches.
- **AT-036f** (markup-safe rendering, LLR-041.11 / B-1): seed `app._validation_issues = [ValidationIssue(code="X", severity=ERROR, message="m", symbol="sensor[red]", address=<in an invalid cell>)]`; `update_memory_map()`; select that cell; assert `#map_detail` renders the **literal** substring `sensor[red]` (brackets present as text) and the app did not raise / the screen still renders. RED: no `#map_detail` → NoMatches (and, pre-fix, a `markup=True` render of `sensor[red]` would raise/strip — the counterfactual).
- **AT-036g** (address-less negative, qa m-5 / R-1 default): seed one issue with `address=None` and one with an in-cell address; select the cell; assert the `address=None` issue appears in **neither** the cell issue list **nor** the "N issues in region" count (locks the operator-confirmed R-1 default).
- **AT-037** (US-037, `case_02`): read `#map_stats`; assert labels for coverage %, bytes covered, valid count, invalid count, gap count + largest gap, total issues; coverage-% value matches TC-041.8's hand-computed number. RED: no `#map_stats` → NoMatches.

> **AT-036b hex assertion (qa m-4):** AT-036b asserts the **rendered hex row** containing `cell_start` appears in `#hex_view` after the jump (behavioral / black-box) — NOT a mock-call assertion on `update_hex_view` (which would be white-box; that call-level check belongs to TC-041.6).

**White-box TCs:** TC-041.1 grid partition (contiguous, non-overlapping, correct windows); TC-041.2 auto-scale — cell-count from an **injected/measured** geometry (not live `panel.size`, for version-stability, qa m-6), `cells ≤ capacity`, zero-span → empty path; TC-041.3 colour class == `css_class_for_severity`; TC-041.4 detail assembler content; TC-041.5 cell→issue join (in-window / `end` excluded / `None` excluded — boundary+negative); TC-041.6 Open computes `focus=cell_start`; TC-041.7 render-only (0 I/O in panel); TC-041.8 stats math — **exact hand-computed literals** for `case_02` (covered bytes, coverage %, gap count, largest-gap bytes), not `>0` (qa m-3); TC-041.9 empty state; TC-041.10 reflow class toggle at 119 vs 120; **TC-041.11 markup-safe render** (a `symbol`/`message` with `[red]`/`[/]`/`[link=…]` + a raw ANSI byte renders literally — no `MarkupError`, no style/ANSI leak).

**Snapshot plan:** **two** drifting/locked cells. (1) `map-comfortable-120x30` (`map` in `_SCAFFOLD_SCREENS`, `test_tui_snapshot.py:109`; scaffold build `:383-392`) drifts from the redesign → mark **xfail-until-baseline**. (2) **ADD `map-comfortable-80x24`** (qa M-2) to lock the narrow-regime reflow (LLR-041.10), exactly as batch-22 added the patch 80×24 floor cell (`:376-378`) — also xfail-until-baseline. Both use `pytest.mark.xfail(reason="baseline-regen-pending: US-035/036/037 minimap redesign", strict=False)`, mirroring the retired batch-22 pattern (`:376-382`); other 27 cells stay green. **Regen canonical-CI-env ONLY** via `snapshot-regen.yml` (pinned `textual==8.2.8`); local regen FORBIDDEN (`[[reference_snapshot_regen_env]]`, batch-25); xfail retired to green only after the CI baselines land.

---

## Draft-time probe ledger (Phase 1, 2026-07-06)

| # | Probe | Result | Consequence |
|---|-------|--------|-------------|
| P-1 | `MemoryMapPanel` | `screens_directionb.py:145-293`; `_BAR_WIDTH=40`(:183), `_EMPTY_TEXT`(:184), `markup=False`(:187), `render_ranges`(:192), `_coverage_bar`(:267), `total_span<=0` guard(:288) | Widget grounded; guards to preserve |
| P-2 | `update_memory_map` | `app.py:7180-7217`; call-site `panel.render_ranges(ranges, range_validity)` :7211-7214 | The ONE app.py call-site to extend (pass issues) |
| P-3 | `_compose_screen_map` | `app.py:1322-1362`; mounts panel in `ScrollableContainer#map_content` + `EmptyStatePanel` | Reflow lives in `#map_content`; empty state preserved |
| P-4 | `update_hex_view` | `app.py:7219-7256`, `focus_address: Optional[int]`, focus math :7229-7235 | Open-in-Hex reuses verbatim (LLR-041.6) |
| P-5 | grep `_validation_issues`/`ValidationReport` | declared `app.py:763-764`, set :6295-6296/:6602-6603, cleared :6090-6091/:7716-7717; `ValidationReport(issues,coverage)` `engine.py:15-18` | Issue-list handoff attr = `_validation_issues` |
| P-6 | `ValidationIssue` | `validation/model.py:121-129`: `code, severity, message, artifact, symbol, address(Optional[int])` | Detail fields confirmed; `address` Optional → boundary/R-1 |
| P-7 | `LoadedFile` | `models.py:46-47` `ranges: List[Tuple[int,int]]` end-exclusive, `range_validity: List[bool]` | Grid inputs confirmed |
| P-8 | `color_policy` | `SEVERITY_CLASS_MAP` :5-11, `css_class_for_severity` :17; ERROR→sev-error, OK→sev-ok, NEUTRAL→sev-neutral | Colour routing (LLR-041.3); frozen → read-only |
| P-9 | grep `width-narrow`/`on_resize` | `_apply_width_regime` `app.py:3919-3952` (`narrow = width<120`), `on_resize` :3954-3956; narrow CSS `styles.tcss:204-216` | Reflow reuses existing breakpoint (LLR-041.10) |
| P-10 | map/rail geometry | `#map_content` `styles.tcss:511-527`, `#activity_rail width:22`:941/`:4` narrow:977-980, `#workspace_body 1fr`:131 | C-13 budget §6.2 grounded |
| P-11 | engine-frozen census (change-first) | planned files = `screens_directionb.py`, `app.py`, `styles.tcss`, tests, REQUIREMENTS.md — ALL outside the frozen set; `color_policy.py`/`validation/` consumed read-only | Best-effort + gate-confirmed (A-2) |
| P-12 | `ls` fixtures | `case_04_bad_checksums/firmware.s19`, `case_02_gaps_and_patch_targets/firmware.s19` present | AT fixtures confirmed |

---

## Evidence checklist (Phase-1 gate)
- ✓ Constraints stated explicitly — §2.4 (render-only, colour-routing, engine-frozen, reflow-reuse).
- ✓ Every code symbol cited `file:line` or flagged NEW/assumed — probe ledger P-1..P-12; NEW helpers flagged in LLR-041.1/.4.
- ✓ C-13 geometry budget COMPUTED both regimes — §6.2 (wide: 62-col grid beside 36-col detail in 98-col body; narrow: stacked); post-chrome widths flagged `assumed — measure in Phase 3`.
- ✓ Two-layer requirements — §3 Acceptance blocks (AT-035/036a-e/037) + §5.2 dual traceability.
- ✓ C-10 non-default-cell AT (AT-036a) + per-branch ATs (AT-036c/d/e) — §7.
- ✓ Render-only LLR (041.7) + colour-routing LLR (041.3) — explicit.
- ✓ Boundary catalog per story (empty/boundary/invalid/error) — §3 QC-3 rows.
- ✓ Fixtures exist — P-12.
- ✓ Engine-frozen census change-first — P-11.
- ✓ Open decision R-1 (address-less issue surfacing) — RESOLVED by operator: region-count line only, no banner; locked by negative AT-036g.
- ✓ R-2 (issue-address density, HIGH) — invalid-cell AT-036d PINNED to the deterministic seed-issue path (qa M-1).
- ✓ B-1 markup injection (Phase-2 blocker) — RESOLVED: LLR-041.11 markup-safe rendering (`Text`/escape, panel-side) + TC-041.11 + AT-036f; 0 frozen diff.
- ✓ Phase-2 majors — MAJOR-2 (`may`) reworded; M-1 (AT-036d) pinned; M-2 (80×24 snapshot) added; minors folded (§6.5).
