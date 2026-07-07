# batch-27 — commit message + PR body (R-TUI-041 interactive Memory Map minimap)

## Commit message

```
feat(tui): interactive color-coded Memory Map minimap (R-TUI-041, batch-27)

Replace the read-only monochrome per-range text list on the Memory Map
screen with an interactive color-coded spatial minimap.

- US-035: auto-scaled colour grid (valid=green / invalid=red / gap=grey,
  routed through css_class_for_severity) + "≈ N KiB/cell" header.
- US-036: click / Tab / arrow-key cell selection -> detail pane (status
  chip, address window, covering region, cell-scoped validation issues +
  region-issue count) + "Open in Hex View" jump (drives the existing
  update_hex_view(focus_address=cell_start)).
- US-037: seven-metric coverage stats strip + two-regime detail reflow
  (beside the grid >=120 cols, stacked below <120 via the existing
  width-narrow breakpoint).

New requirement R-TUI-041 supersedes the read-only R-TUI-026. The panel
stays render-only: it reads the already-computed LoadedFile.ranges /
range_validity and the pre-computed ValidationReport issues and does no
parsing, coverage computation or validation of its own. Zero changes to
the engine-frozen set (core/hexfile/range_index/validation/a2l/mac/
color_policy).

Security (LLR-041.11): colouring flips the panel to Rich-markup rendering
over file-derived issue text (message/symbol/code); all such text is
rendered markup-safe via explicit-style rich.text.Text so a hostile A2L
symbol (e.g. `sensor[red]` or an embedded ANSI/link payload) renders
literally and cannot corrupt or crash the screen.

Tests: 1037 -> 1058 (net +21; -3 superseded text-list TC-025, +24 new).
14 white-box TC (LLR-041.1..11) + 11 black-box AT (US-035/036/037) driven
through #screen_map via Textual Pilot. The two Memory Map snapshot cells
(map-comfortable-120x30 + 80x24) are xfail-until-baseline pending a
canonical-CI baseline regen.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
```

## PR body

```markdown
## What & why

The Memory Map screen was a monochrome, read-only text list — one bar per
range, no colour, no interaction. This replaces it with an **interactive
colour-coded spatial minimap** so an operator can see an image's coverage
shape at a glance, drill into any address window, and jump to the bytes.

Design was operator-approved via a throwaway prototype before implementation.

## Changes (R-TUI-041, supersedes read-only R-TUI-026)

- **US-035 — colour grid:** each cell is an auto-scaled address window,
  coloured valid/invalid/gap through `css_class_for_severity`; header shows
  `≈ N KiB/cell`.
- **US-036 — selection + detail:** click / Tab / **arrow-key** navigation
  selects a cell; the detail pane shows status chip, address window, covering
  region, the validation issues anchored in that cell (+ a region-issue
  count), and an "Open in Hex View" jump.
- **US-037 — stats + reflow:** a seven-metric coverage strip (coverage %,
  bytes covered, valid/invalid counts, gaps, largest gap, total issues) and a
  two-regime layout (detail beside the grid ≥120 cols, stacked below <120).

## Security

Colouring the panel enables Rich-markup rendering over **file-derived** issue
text. `LLR-041.11` renders all such text markup-safe (explicit-style
`rich.text.Text`), so a malformed A2L symbol like `sensor[red]` renders
literally instead of corrupting/crashing the screen. Caught by independent
Phase-2 review before any code shipped.

## Contract preserved

- **Render-only:** panel reads already-computed `LoadedFile.ranges` /
  `range_validity` + `ValidationReport` issues; no new analysis.
- **Engine-frozen:** 0 diffs to core/hexfile/range_index/validation/a2l/mac/
  color_policy (guarded by `test_engine_unchanged` + TC-031).

## Testing

- Test count 1037 → **1058** (14 white-box TC + 11 black-box AT).
- Black-box ATs drive the real `#screen_map` via Textual Pilot (select cells,
  press arrows, trigger Open-in-Hex, read the rendered widgets) with boundary
  + negative coverage (empty, single-range, invalid, gap, address-less issue,
  zero-span, arrow edge-clamp, focus-no-scroll, markup/ANSI injection).
- `test_tui_directionb.py` + engine guard: **122 passed**.
- Snapshot suite: 30 passed / **2 xfailed** — the two Memory Map cells
  (`map-comfortable-120x30`, `map-comfortable-80x24`) are
  **xfail-until-baseline**; SVG baselines regenerate in the canonical CI env
  (`snapshot-regen.yml`, pinned `textual==8.2.8`) post-merge, then the xfails
  are retired. Local regen is intentionally avoided.

## Post-merge follow-ups

- [ ] Regenerate the 2 Memory Map snapshot baselines in canonical CI, retire the xfails.
- [ ] (Backlog) coverage-% display polish; A2L-symbol region names; Bookmarks screen.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```
