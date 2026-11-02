# Chapter 14 — Split / Join / Export

**Window:** Split / Join / Export (W21). **How to get there:** command palette only —
`^k`, type `split`, Enter. It has no rail key. `esc` closes it back to the window
you came from.
**Demo inputs:** `firmware.s19` + `firmware.a2l`.

## What this window is for

It cuts the loaded image into pieces and writes them out: one file per range
(**split**) or several ranges packed into one file (**join**), as S19, HEX or BIN.

## Step by step

### 14.1 Open it from the palette

![Palette](img/ch14-01-palette-split.png)

`^k` opens the command palette; typing `split` leaves one entry, *Split / Join /
Export*; Enter opens the window.

### 14.2 The window

![Ranges](img/ch14-02-split-join-ranges.png)

- **SEGMENTS** — three sources: `a2l(n)` (the A2L's `MEMORY_SEGMENT`s),
  `ranges(n)` (the image's own contiguous ranges) and `manual(n)` (ranges you
  type). With the demo A2L loaded the A2L source shows `a2l(0)` although the file
  declares four segments (finding F-29); the window opens on `ranges(4)`.
- The range table: name, start, size, and how many source bytes the range holds.
- **MODE** split / join, **INTRA GAP** (split: skip / fill) or **JOIN GAPS** (join:
  concat / fill) with **PAD** (0x00 / 0xFF), **FORMAT** S19 / HEX / BIN, **DEST**
  project / common, **NAMING** (fixed `‹stem›_‹segment›`, with a live sample file
  name).
- **PREVIEW** (right) — the output band, the files, the legend, the address ruler,
  a summary and **EXPORT e**.

The key bar lists the window keys: `space` Tick, `a` All, `n` None, `t` Source,
`m` Mode, `g` Gap, `f` Format, `p` Pad, `d` Dest, `e` Export, `esc` Close. ↑ ↓ (or
`k` `j`) move the cursor. While the window has focus these keys replace the global
`k`, `j`, `g`, `f`, `p`, `d`, `t`.

### 14.3 Tick ranges

![Ticked](img/ch14-03-split-ticked.png)

`space` ticks the range under the cursor (`●`). With `range_00` and `range_02`
ticked, the preview lists two files, `firmware_range_00.s19` (64 KiB) and
`firmware_range_02.s19` (1.20 MiB).

### 14.4 Export in split mode

![Exported](img/ch14-04-split-exported.png)

`e` writes one file per ticked range: *Exported 2 files: wrote
firmware_range_00.s19; wrote firmware_range_02.s19 → …* (into the work area's
common folder, as no project is open).

### 14.5 Join, concatenated

![Join concat](img/ch14-05-join-concat.png)

`m` switches to **join**: the ticked ranges become one file, `firmware_joined.s19`.
With **concat** the ranges are packed back to back (`concat: offsets remapped`).

### 14.6 Join with fill

![Join fill](img/ch14-06-join-fill.png)

`g` switches to **fill**: the ranges keep their addresses and the gap between them is
padded. The span here is 9.20 MiB, so a **GUARD** warns that `e` will ask first.

### 14.7 Export refused

![Export refused](img/ch14-07-join-span-guard-arm.png)

`e` refuses this export: *export aborted: 2.77 MiB of source bytes sit inside a padded
gap*. `range_01`, not ticked, lies inside the gap, and the fill never overwrites real
bytes. Tick it too (or use concat) to export.

### 14.8 Format and pad

![Format and pad](img/ch14-08-join-format-pad.png)

`f` cycles the format (here HEX — the sample name becomes `firmware_joined.hex`), `p`
the pad byte (`0xFF`).

### 14.9 Manual ranges

![Manual empty](img/ch14-09-source-manual-empty.png)

`t` cycles the source; on `manual` a text box opens for `0xSTART-0xEND` lines. The
`t` that switches to this tab is also typed into the box (finding F-18).

![Manual typed](img/ch14-10-source-manual-typed.png)

After typing `0x00C00000-0x00C000FF` the table shows `locality_00`, 256 B. Every
partial line while typing logs a *manual: dropped …* message.

### 14.10 Close

![Closed](img/ch14-11-split-join-closed.png)

`esc` (with the focus in the table) returns to the window you came from.

### 14.11 Wide terminal

![Join wide](img/ch14-12-join-wide.png)

At 220×60: `a` ticks all four ranges and `m` joins them — 4.05 MiB packed with
concat.

## Features of this window

| Feature | How | Capture |
|---|---|---|
| Open from the palette | `^k` "split" | 14.1 |
| Sources a2l / ranges / manual | `t` | 14.2, 14.9 |
| Cursor, tick, all, none | ↑ ↓ `k` `j`, `space`, `a`, `n` | 14.3, 14.11 |
| Manual localities box | type | 14.9 |
| Mode split / join | `m` | 14.5 |
| Gap skip-fill / concat-fill | `g` | 14.6 |
| Format, pad, destination | `f`, `p`, `d` | 14.8 |
| Naming sample | — | 14.2 |
| Preview band, files, ruler, guard | — | 14.3, 14.6 |
| Export (with refusal and two-step confirm) | `e` / EXPORT | 14.4, 14.7 |
| Close | `esc` | 14.10 |
