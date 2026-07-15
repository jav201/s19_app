# Functionality — s19_app — Batch 2026-07-14-batch-45

## What it does
The **Memory Map** screen now visualizes the loaded firmware image's **entropy** instead of only
its validation status. Previously a real image showed a mostly-grey cell grid (only valid/invalid/gap
colouring); now it shows, at a glance, which regions are code, calibration data, lookup tables, or
padding.

### The band view (R-TUI-060)
- A **proportional segmented band bar**: contiguous memory windows of the same entropy band are merged
  into one segment whose width is proportional to its byte size. Same-band regions separated by an
  address gap stay **separate** (they are not falsely merged into one contiguous span).
- A **per-region list**: one row per merged region showing `{glyph} 0x{start} · {N} B · {band}`.
- Each segment/row is **colour-coded AND texture-coded** by band (`· constant/padding`, `░ low`,
  `▒ medium`, `▓ high/random`) — the texture glyph means the bands read even without colour.
- Bands come from the existing `entropy_service.compute_entropy` (constant/padding · low · medium ·
  high/random); colours from a new non-frozen `entropy_style` map (kept separate from the frozen
  severity colours).

### At a glance (R-TUI-061)
A docked panel showing a **per-band histogram** (count + %) and an **entropy profile sparkline** across
the address space. It docks beside the band bar on wide terminals and stacks below it at the 80×24 floor.

### Single-click navigation (R-TUI-062)
Clicking a region row **once** repositions the hex view to that region's start address and switches to
the workspace — replacing the old two-step (select a cell, then press an "Open in Hex" button). The
region's detail (including any overlapping A2L symbol names) is shown in the detail pane on selection.

### Retirement
The standalone entropy pop-up (the `e` key) is **removed** — the always-visible map band view provides
its function (all regions shown at once, a band legend, per-region navigation), so paging and sort are
no longer needed.

## How entropy is computed
Entropy is computed once on the **worker thread** during file load (`build_loaded_s19/hex`) and cached
on `LoadedFile.entropy_windows`; the renderer only reads it (never recomputes), keeping the UI thread
responsive on large images.

## Non-goals / notes
- The band bar's width is fixed (60 glyphs) and clips cosmetically at narrow-shared layouts — a
  responsive width is a future polish.
- Markdown/HTML reports are unaffected. The engine (parsers/validation) is unchanged.
