# Functionality — Interactive Memory Map — s19_app — Batch 2026-07-06-batch-27

> **Audience:** technical stakeholders and engineers who want to understand *what the redesigned Memory Map screen does* and *how it is wired*, without reading the full requirements set.
> **Purpose:** understand the feature (R-TUI-041). BLUF first, then detail.

---

## BLUF

The **Memory Map** rail screen (`s19tui`, rail key `4`, `#screen_map`) is now an **interactive, colour-coded spatial minimap** of the loaded firmware image, replacing the old read-only monochrome per-range text list. At a glance the operator sees the whole image's coverage *shape* — green cells for valid regions, red for invalid, grey for gaps — auto-scaled so the entire address span fits one grid. Selecting any cell (click, `Tab`, or arrow keys + `Enter`) opens a **detail pane** showing that cell's status, address window, covering region, and the validation issues anchored inside it, plus a one-key **jump into the hex view** at the cell's start address. A **coverage stats strip** underneath gives the quantitative summary (coverage %, bytes covered, valid/invalid counts, gaps, largest gap, total issues).

Critically, the panel is **render-only**: it computes no new coverage, parsing, or validation. It reads the already-computed `LoadedFile.ranges` / `range_validity` and the pre-computed `ValidationReport` issues, and derives cells and stats by arithmetic on those already-parsed values. The engine-frozen boundary is untouched — `git diff main` over the seven frozen parser/validation modules is empty.

---

## 1. Before vs. after

| Aspect | Before (R-TUI-026, monochrome text list) | After (R-TUI-041, interactive minimap) |
|--------|------------------------------------------|----------------------------------------|
| Body | A single scrollable `Static`, `markup=False`, printing **one text line per range + gap** with a `#`-fill bar (`_BAR_WIDTH=40`) | A **2-D grid of coloured cell widgets** (`#map_grid` of `.map-cell`), one tile per auto-scaled address window |
| Colour | None — monochrome text | **Valid = green · invalid = red · gap = grey**, routed through `css_class_for_severity` |
| Spatial sense | Read the list line by line | See the whole image's coverage shape at once |
| Interactivity | None (read-only text) | **Select a cell** → detail pane; **Open in Hex View** jump; keyboard navigation |
| Per-cell scale | Implicit in the bar width | Explicit **"≈ N KiB/cell"** header |
| Detail | None | Status chip · address window · covering region · cell-scoped issues · region issue count |
| Quantitative summary | None | **7-metric coverage stats strip** |
| Layout | Single scroll column | Two-regime reflow: detail beside the grid (wide) / below it (narrow) |

The read-only contract is the one thing that did **not** change: R-TUI-026's "render from `ranges`/`range_validity`, compute no new coverage data" is retained and *strengthened* as LLR-041.7.

---

## 2. The colour-coded grid (US-035)

The grid renders the image's **memory span** — `[min(start), max(end))` over all ranges — as a wrapping grid of cells. Each cell is a contiguous half-open **address window** `[cell_start, cell_end)`, coloured by the ranges that overlap it:

- **Valid (green, `sev-ok`)** — the cell overlaps only valid range(s).
- **Invalid (red, `sev-error`)** — the cell overlaps any invalid range (invalid wins, so a cell straddling a valid and an invalid range reads red).
- **Gap (grey, `sev-neutral`)** — the cell overlaps no range at all.

Colours are **never hard-coded**. The status (`"valid"`/`"invalid"`/`"gap"`) is mapped to a `ValidationSeverity` and routed through the frozen `css_class_for_severity` — the single source of truth for `sev-*` CSS classes, shared with every other severity surface in the TUI (`status_to_css_class`, `screens_directionb.py:333`). The cell glyph is a filled block `█`; its colour comes purely from the applied CSS class.

**Auto-scaling.** Cell size adapts so the whole image fits the visible grid:

1. `derive_image_span(ranges)` → the span in bytes.
2. `cell_count_for_geometry(span, cols, rows)` → `min(cols*rows, span)` cells — never more cells than there are bytes, capped to the measured grid capacity.
3. `bytes_per_cell(span, cell_count)` → `ceil(span / cell_count)`.

The header then shows, e.g., **"≈ 2.00 KiB/cell (128 cells, 2048 B/cell)"** so the operator always knows the resolution. When the span is `0` (no ranges, or a degenerate zero-span) the panel shows a neutral empty note and **computes no ratio** — the `span > 0` check is the single divide-by-zero guard.

**Snapshot-stability note:** the cell *count* is a pure function of `(span, geometry)` — the helper arithmetic never reads live layout, so the SVG snapshot is deterministic. The shipped panel reads the live `#map_grid.content_size` for geometry, falling back to fixed `DEFAULT_GRID_COLS=16` / `DEFAULT_GRID_ROWS=8` when unmeasured (headless renders).

---

## 3. Cell selection and the detail pane (US-036)

Selecting a cell drives the detail pane (`#map_detail_body`). There are three ways to select:

- **Click** a cell — focuses it and posts `MapCell.Selected`.
- **`Tab` / `Shift+Tab`** — Textual's default focus traversal steps cell to cell (each `MapCell` is `can_focus`); `Enter` selects the focused cell.
- **Arrow keys** — Left/Right move focus ±1 cell in mount order; Up/Down move ±one visual row (`± cols`); focus clamps at the grid edges (no wrap). Arrows only *move* focus; `Enter` selects. A discoverability hint is shown before any selection: *"Click a cell, or focus the grid and use arrows (←/→/↑/↓) then Enter to inspect."*

> The arrow-key navigation was added in an Increment-2 follow-on: the panel's docstring and the approved prototype promised arrow navigation, but Textual does no spatial arrow-focus by default, so it had to be implemented explicitly (`adjacent_cell_index` + `focus_adjacent_cell`). Arrow handling is scoped to the focused cell and consumes the key (`event.stop()`) only when it handles an arrow, so it does not leak into scrolling the enclosing `#map_content` — verified by an assertion that `scroll_offset.y` is unchanged.

On selection, `build_detail_text` composes the detail body for `[cell_start, cell_end)`:

- **Status chip** — `VALID` / `INVALID` / `GAP (uncovered)`.
- **Address window** — `Cell: 0x{cell_start:08X}-0x{cell_end-1:08X}`.
- **Covering region** — the first range overlapping the cell (invalid-preferred so the region status matches the cell colour), shown as `Region: 0x…-0x… (N bytes, valid|invalid)`; or `Region: gap - no region` for a gap cell.
- **Cell-scoped issues** — the validation issues whose `address` falls inside the cell window, each rendered as `[code] 0x{address:08X} {symbol} {message}`, preceded by a `N issue(s) in this cell` count.
- **Region issue count** — a one-line `N issue(s) in region` = issues whose address falls in the covering range.

**Issue anchoring (read-only join, no new analysis).** The detail pane joins the pre-computed `_validation_issues` list against the cell/region windows via the pure `issues_in_window` helper. Issues with `address is None` **cannot be spatially anchored** and are excluded from both the cell list and the region count — the operator-confirmed default (locked by the negative test AT-036g). This is a display-time filter over the already-computed issue list, not a new query.

**Open in Hex View.** When a cell is selected, an "Open in Hex View" button is revealed. Pressing it posts `MemoryMapPanel.OpenInHexRequested(focus_address=cell_start)`. The app-side handler `on_memory_map_panel_open_in_hex_requested` switches to the Workspace/hex screen and drives the **existing** `update_hex_view(focus_address=cell_start)` — the panel renders no hex itself. This reuses the pre-existing focus path verbatim (`app.py:7249`), so the hex view scrolls to and highlights the row containing the cell's start address.

---

## 4. The coverage stats strip (US-037)

Below the grid, `#map_stats` shows seven statistics derived by `coverage_stats(...)` from the same already-parsed inputs the grid is built from:

| Metric | Derivation |
|--------|------------|
| Coverage % | `covered_bytes / image_span * 100` (only when `image_span > 0`) |
| Bytes covered | `Σ(end - start)` over all ranges |
| Valid ranges | count of `range_validity[i] == True` |
| Invalid ranges | count of `range_validity[i] == False` |
| Gaps | number of positive spans between consecutive ranges |
| Largest gap | the widest inter-range gap, in bytes |
| Total issues | `len(_validation_issues)` |

This is **display arithmetic on already-parsed addresses**, mirroring the same covered-bytes / span / gap subtraction the old text list used — not new analysis. The `image_span > 0` check is the single divide-by-zero guard; an empty image yields an all-zero `CoverageStats` and a blank strip.

For the public `case_02_gaps_and_patch_targets` fixture the strip's numbers are pinned to exact hand-computed literals (test TC-041.8): span `0x80010140`, covered `93 B`, coverage `0.000004%`, gaps `3`, largest gap `2,147,549,173 B`, valid `4`, invalid `0`, issues `0`.

> **Canonical stats source.** Both the stats strip and the LLR-041.5 detail join read the **single canonical** `_validation_issues` list handed into `update_memory_map` — never `_validation_report.coverage` or a re-derived count. This avoids two divergent issue counts on the same screen.

---

## 5. Two-regime reflow (LLR-041.10)

The detail pane repositions with terminal width, reusing the app's **existing** `width-narrow` breakpoint (toggled by `_apply_width_regime` / `on_resize` at width 120) — no second breakpoint was invented:

- **Wide (≥ 120 cols):** `#map_body` is horizontal — the grid takes the `1fr` remainder beside a fixed **36-col** `#map_detail` right column. The geometry budget was computed *and* measured: in a 120-col terminal the body is `98` cols (rail 22), the grid gets `98 − 36 = 62` cols — a positive, elastic remainder (measured live: grid at x26, detail 36 wide at x78, same row; no clip).
- **Narrow (< 120 cols):** `#map_body` stacks vertically — grid full-width, detail below it. No horizontal fixed-sibling contention; vertical overflow scrolls (`#map_content` is a `ScrollableContainer`). The rail collapses to 4 cols, so even at the 80-col minimum the grid has `76` cols.

The header and the stats strip span the full panel width in both regimes.

---

## 6. Security — markup-safe rendering of file-derived text (LLR-041.11)

Colouring cells requires Rich **markup** to be enabled (`markup=True`) — a change from the old panel's `markup=False`. That flip creates an injection surface: a loaded A2L/MAC symbol such as `sensor[red]` or `x[link=file:///…]` would otherwise be parsed as Rich markup, corrupting the render, injecting styling, or raising `rich.errors.MarkupError` that would **crash the Memory Map screen on load** — squarely on the tool's core untrusted-input path.

The fix is panel-side (0 engine-frozen diff): every file-derived string reaching the grid or detail pane — `ValidationIssue.message`, `.symbol`, `.code`, and any covering-region name — is composed as a `rich.text.Text` with explicit styles via the `safe_text` helper, so the value is treated as **literal text**, never markup. The `Text`-with-explicit-styles approach is deliberately preferred over bare `rich.markup.escape` because it *also* neutralises raw ANSI bytes carried in the never-scrubbed `ValidationIssue.symbol` field (the upstream `_scrub_issue_message` strips ANSI only from `.message`, never touches `.symbol`, and is engine-frozen). This is validated both white-box (TC-041.11 feeds `[red]`/`[/]`/`[link=…]` + a raw ANSI byte, asserts literal render, no `MarkupError`) and black-box (AT-036f seeds `symbol="sensor[red]"`, selects the cell, asserts the literal brackets appear in `#map_detail` and the screen does not crash).

---

## 7. The render-only contract and the engine-frozen boundary

Two invariants bound this batch:

**Render-only (LLR-041.7).** `MemoryMapPanel` performs no parsing, coverage computation, validation, or file I/O. It consumes exactly the arguments handed to it by `update_memory_map` — `ranges`, `range_validity`, and the pre-computed issue list — and derives cells and stats by arithmetic on those already-parsed values. This is verified by inspection: an AST scan of the panel body returns zero I/O hits (`open(`, `Path(`, `parse_`, `validate_`, `build_loaded`, `read_text`, `load(`), plus the pre-existing `test_tc028_…` inspection of `update_memory_map`.

**Engine-frozen (§2.4 / HLR constraint).** No file in the frozen set — `core.py`, `hexfile.py`, `range_index.py`, `validation/`, `tui/a2l.py`, `tui/mac.py`, `tui/color_policy.py` — is modified. `css_class_for_severity`, `SEVERITY_CLASS_MAP`, and `ValidationIssue` are all **consumed read-only**. `git diff main` over these paths is empty (`test_engine_unchanged.py` + `test_tc031_*` pass). All new code lives in the view layer (`screens_directionb.py`, `app.py`, `styles.tcss`).

---

## 8. Data sources (verbatim, already-computed)

| Input | Source | Read by |
|-------|--------|---------|
| `ranges: List[Tuple[int,int]]` (end-exclusive) | `LoadedFile.ranges` (`models.py:46`) | grid build, span, stats |
| `range_validity: List[bool]` (positionally aligned) | `LoadedFile.range_validity` (`models.py:47`) | cell status, valid/invalid counts |
| Pre-computed issues | `S19TuiApp._validation_issues` (`app.py:764`) — the single canonical list | detail join + region count + stats total |
| `code` / `severity` / `message` / `symbol` / `address` | `ValidationIssue` (`validation/model.py:121-129`); `address` is `Optional[int]` | detail issue lines (markup-safe) |
| Severity → CSS class | `css_class_for_severity` / `SEVERITY_CLASS_MAP` (`color_policy.py`, **frozen**) | every cell + the detail status chip |
| Focus jump | `update_hex_view(focus_address=…)` (`app.py:7249`, **existing**) | Open-in-Hex |

---

## 9. Assumptions, risks, next steps

**Assumptions.**
- `LoadedFile.ranges` and `range_validity` are positionally aligned and `end`-exclusive (verified `models.py:46-47`).
- The already-computed `_validation_issues` list is current at render time (`update_memory_map` is called on the UI thread after load).
- A bare S19 range has no human name → the detail pane uses its `0x…-0x…` bounds as the region "name" (A2L-symbol naming of regions is out of scope for this batch, deferred — R-3).

**Risks / limitations.**
- Two snapshot cells (`map-comfortable-120x30`, `map-comfortable-80x24`) are **pending-baseline** (xfail-until-baseline) until the canonical-CI regen lands post-merge — a designed state, not a failure.
- A live-geometry lock (`_EXPECTED_MAP_CELLS_120x30 = 128`) must be updated in lockstep with any future layout change + baseline regen.
- Coverage-% renders at `.6f` precision (correct, but shows `0.000004%` for very sparse images); a future polish could adopt adaptive precision. Operator decision.
- Issues with `address is None` appear in neither the cell list nor the region count (by design, R-1); they are not surfaced on this screen.

**Next steps.**
- Regenerate the 2 map snapshot baselines in canonical CI, then retire the xfails to green.
- (Deferred, own batch) A2L-symbol naming of covering regions in the detail pane.
