# Chapter 4 — A2L Explorer

**Windows:** A2L Explorer (W05), Parameter description (W06).
**How to get there:** `2`, or the second rail glyph.
**Demo inputs:** `firmware.s19` + `firmware.a2l` (462 tags: 358 characteristics,
104 measurements; 60 CURVE, 20 MAP).

## What the A2L Explorer is for

It lists every tag of the A2L with its address, length, conversion and whether its
bytes are in the loaded image, and shows those bytes in the hex pane beside the table.

## Step by step

### 4.1 The tag table

![A2L table](img/ch04-01-a2l-table.png)

- **Left** — the filter row (*Filter tags* field, **Field: name**, **All**,
  **Invalid**, **In-Memory**, then a find field and paging buttons, cut off at 118
  columns — finding F-10), the tag table, and the page line
  (*Page 1/3 | tags 1-200 / 462*).
- **Right** — the **detail card** of the highlighted tag (name, address,
  description, unit, conversion, layout or byte order) above the hex viewer.

Each row starts with a glyph (`✓` in image). At 118 columns the Address, Length,
Source and Raw columns run together: `0x00803DE064` is address `0x00803DE0`
followed by length `64` (finding F-09).

### 4.2 The detail card follows the cursor

![Detail card](img/ch04-02-a2l-detail-card.png)

Move with ↑ ↓; the card updates for the highlighted tag (here a measurement with a
table conversion, little-endian).

### 4.3 Filter

![Filter CURVE_](img/ch04-03-a2l-filter-curve.png)

Type in *Filter tags* — here `CURVE_` — and the table narrows as you type (60 tags,
page 1/1). The filter field itself is only two cells wide at this size.

### 4.4 Choose the field to filter on

![Filter field menu](img/ch04-04-a2l-filter-field-menu.png)

**Field: name** opens a list of fields: all, name, address, length, raw and physical
value, source, in_memory, limits, unit, bits, endian, virtual, function group,
access, datatype, description, memory region. Pick one; press the button again to
close the list.

### 4.5 Jump to a tag's bytes

![Row jump](img/ch04-05-a2l-row-jump-hex.png)

Enter (or click) on a row: the hex pane moves to the tag and highlights its bytes in
orange; the log says *Tag at 0x00803E70*.

### 4.6 Describe a CURVE

![Describe CURVE](img/ch04-06-describe-curve.png)

With a CURVE row highlighted, press `d`. The **Parameter** dialog shows the A2L
metadata, the conversion, the axis, every point decoded from the loaded image, a
small shape plot, and notes (here: the layout has no axis points, so x is the point
index). `esc` or **Close** closes it.

### 4.7 Describe a MAP

![Describe MAP](img/ch04-07-describe-map.png)

For a MAP (`MAP_0001`, reached by filtering on its name) the dialog lists both axes
and the flattened value run; a note says a 2-D grid view is not part of the
description yet. A scalar tag opens the same dialog with a "not a curve" header.

### 4.8 In-Memory filter

![In-Memory](img/ch04-08-a2l-filter-in-memory.png)

**In-Memory** keeps only tags whose bytes are in the image — all 462 in the clean
demo file. **Invalid** keeps tags with a validation fault (none here); **All**
clears the filter.

### 4.9 Page through the table

![Page next](img/ch04-09-a2l-page-next.png)

`+` (or PgDn, or **Page Next**) shows the next 200 tags; `-` (PgUp, **Page Prev**)
the previous ones. The page size can be changed in Viewer settings (Chapter 19).

### 4.10 Find a tag by name

![Find in table](img/ch04-10-a2l-find-in-table.png)

Type a name in *Find in tag table* and press **Find next**: the table jumps to the
page that holds it and marks the row (*Tag find: MEASUREMENT_0065 (row 409)*).

### 4.11 Dump the A2L as JSON

![Dump JSON](img/ch04-11-a2l-dump-json.png)

`j` writes the parsed A2L to `workarea\temp\firmware.a2l.json` for other tools; the
log confirms *A2L JSON saved: firmware.a2l.json*.

### Also on this window

`/` and `g` work in the hex pane (as on the Workspace); `,` `.` page it; `k` opens
the legend with the A2L colour rows.

## Features of these windows

| Feature | How | Capture |
|---|---|---|
| Tag table with severity glyphs | — | 4.1 |
| Detail card | ↑ ↓ | 4.2 |
| Filter text | type | 4.3 |
| Filter-field menu | Field: button | 4.4 |
| All / Invalid / In-Memory | buttons | 4.8 |
| Find in tag table + Find next | type, button | 4.10 |
| Paging | `+` `-`, PgDn/PgUp, buttons | 4.9 |
| Row → hex jump + highlight | Enter / click | 4.5 |
| Describe tag (CURVE, MAP, scalar) | `d` | 4.6, 4.7 |
| Dump A2L JSON | `j` | 4.11 |
| Hex search / goto / paging, legend | `/` `g` `,` `.` `k` | text |
