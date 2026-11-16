"""The pure render of the Patch Editor's array, curve and map benches (Inc 9, group B2).

Builds the rich ``Text`` lines of a bench: the selected row's detail (the
definition line, the grid or chart canvas, the window line, the legend, the
tool row and the bytes line), the grid and chart canvases, the axis labels and
the legend line.  The state, the grid and the values live in
``definition_bench.py``; the widget that paints these lines is
``patch_editor/bench_sheet.py``.  No ``textual`` import; every untrusted word is
written through Inc 8's ``plain`` and every line is cut to the sheet's width.

Unit U4 holds: ``bench_detail``, ``grid_canvas``, ``chart_canvas``,
``axis_labels``, ``legend_line``.  Unit U5 holds: ``tool_row``,
``window_line``, ``bytes_line``, ``op_line``.
"""

from __future__ import annotations

import math

from rich.style import Style
from rich.text import Text

from .a2l_definition import (
    Decoded,
    DecodedAxis,
    Definition,
    Encoded,
    Refusal,
    display_text,
)
from .definition_sheet import (
    Preview,
    SheetRow,
    _FALLBACK_OPS,
    clip,
    name_echo,
    plain,
    short_number,
)
from .insight_style import DEPTH_BG
from .definition_bench import (
    _TOOL_LABELS,
    BenchState,
    BenchValues,
    Grid,
    bench_grid,
    count_text,
    finite_range,
    ramp_step,
    ramp_style,
    selection_cells,
    where_text,
)

ACCENT = "#91abec"
EDIT = "bold #f5c26b"
#: EDIT's foreground as a hex colour (EDIT itself is a style string): the busy cue's border and pill.
BUSY_COLOR = Style.parse(EDIT).color.get_truecolor().hex

#: The eighth blocks of a chart bar, level 0..8 -> index (0 is a space).
_BLOCKS = " ▁▂▃▄▅▆▇█"

#: The chart's left label column: the hi / lo text right-aligned in 8 cells, then a space.
_CHART_LABEL = 9

#: The cells of the formula bar's name label (Inc 8's ``#patch_sheet_name`` max-width).
_NAME_CELLS = 28


# --------------------------------------------------------------------------- helpers


def _cut(line: Text, width: int) -> Text:
    """``line`` cut to ``width`` cells with one ``…`` (never wider)."""
    if line.cell_len <= width:
        return line
    line = line.copy()
    line.truncate(width, overflow="ellipsis")
    return line


def _fit(content: str, width: int, style: str = "", align: str = "left") -> Text:
    """``content`` padded (or cut) to exactly ``width`` cells, aligned."""
    text = Text(content, style=style)
    if text.cell_len > width:
        text = text.copy()
        text.truncate(width, overflow="ellipsis", pad=True)
        return text
    pad = width - text.cell_len
    if align == "right":
        return Text(" " * pad, style=style).append_text(text)
    if align == "center":
        left = pad // 2
        return Text(" " * left, style=style).append_text(text).append(" " * (pad - left), style=style)
    return text.append(" " * pad, style=style)


def _cell_number(text: str) -> float | None:
    """The edit text as a finite double, else ``None``."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def grid_geometry(width: int, grid: Grid) -> tuple[int, int]:
    """(columns shown nc, cell width cw) of CTX-PE-BENCH, never dividing by zero."""
    nc = max(1, min(grid.nx, (width - 6) // 6))
    cw = max(5, min(20, (width - 6) // nc - 1))
    return nc, cw


def grid_rows_shown(room: int, grid: Grid) -> tuple[int, bool]:
    """(grid rows shown, two terminal rows per grid row)."""
    if 2 * grid.ny <= room - 1:
        return grid.ny, True
    return min(grid.ny, max(1, room - 1)), False


def _canvas_labels(state: BenchState, definition: Definition, grid: Grid) -> tuple:
    """The stored column and row labels, or the index form when absent."""
    if state.labels is not None:
        return state.labels
    return axis_labels(definition, (), grid)


def _shown_value(
    definition: Definition, values: BenchValues, staged: BenchValues | None,
    state: BenchState, position: tuple, index: int,
) -> tuple:
    """(shown number, text, edited) of one element: pending, staged, else current."""
    if position in state.edit:
        return _cell_number(state.edit[position]), plain(state.edit[position]), True
    if index in values.missing:
        raw = values.texts[index] if values.texts is not None else ""
        return None, plain(raw) if raw else "--", False
    number = values.numbers[index]
    if (
        staged is not None
        and index not in staged.missing
        and math.isfinite(staged.numbers[index])
        and staged.numbers[index] != number
    ):
        return staged.numbers[index], display_text(definition, staged.numbers[index]), True
    return number, display_text(definition, number), False


def _grid_cell(
    definition: Definition, grid: Grid, values: BenchValues, staged: BenchValues | None,
    state: BenchState, col: int, row: int, cw: int, selected: bool, two_rows: bool,
) -> Text:
    """One grid cell: the value text centred, shaded, edited cells bold + ``*``."""
    index = col + grid.nx * row
    if index >= grid.count:
        return _fit("", cw)
    position = (col, row) if grid.layout == "2d" else (index,)
    number, text, edited = _shown_value(definition, values, staged, state, position, index)
    style = ramp_style(ramp_step(number, state.lo, state.hi)) if number is not None and math.isfinite(number) else ""
    if edited:
        style = ("bold " + style).strip()
        if cw >= 6:
            text += "*"
    if not two_rows and selected:
        style = (style + " underline").strip()
    if state.focus and (col, row) == state.cursor:
        text = "▸" + text
    return _fit(text, cw, style=style, align="center")


def _grid_header(columns: tuple, origin_col: int, nc: int, cw: int) -> Text:
    """The grid's column-label header (a 6-cell row-label gutter on the left)."""
    line = Text(" " * 6)
    for k in range(nc):
        col = origin_col + k
        label = columns[col] if col < len(columns) else ""
        line.append_text(_fit(label, cw, align="center"))
        if k < nc - 1:
            line.append(" ")
    return line


def _grid_bar_row(
    grid: Grid, origin_col: int, nc: int, cw: int, row: int,
    lo_c: int, hi_c: int, lo_r: int, hi_r: int,
) -> Text:
    """The bar row under one grid row: ``▀`` in the accent under selected cells."""
    bar = Text(" " * 6)
    for k in range(nc):
        col = origin_col + k
        if lo_c <= col <= hi_c and lo_r <= row <= hi_r and col + grid.nx * row < grid.count:
            bar.append("▀" * cw, style=ACCENT)
        else:
            bar.append(" " * cw)
        if k < nc - 1:
            bar.append(" ")
    return bar


def _axis_point_labels(axis: DecodedAxis | None, letter: str, count: int) -> list[str]:
    """An axis's point texts, or the index form for a missing or refused point."""
    labels = []
    for i in range(count):
        point = None
        if axis is not None and axis.points is not None and i < len(axis.points):
            point = axis.points[i]
        if point is None or isinstance(point, Refusal):
            labels.append(f"{letter}{i}")
        else:
            labels.append(plain(point.text))
    return labels


def _eighths(value: float | None, lo: float, hi: float, h: int) -> int | None:
    """The bar height in eighths of ``value`` over base..hi; half when lo == hi."""
    if value is None or not math.isfinite(value):
        return None
    if hi == lo:
        return h * 4
    base = lo - (hi - lo) / 10
    return round((value - base) / (hi - base) * h * 8)


def _block(e: int | None, h: int, i: int) -> str:
    """The eighth block of bar ``e`` in row ``i`` (0 = top); a space when none."""
    if e is None:
        return " "
    filled = max(0, min(8, e - (h - 1 - i) * 8))
    return _BLOCKS[filled]


def chart_geometry(width: int, grid: Grid, origin_col: int) -> tuple[int, int]:
    """(column width cwid, points shown n) of a chart window."""
    total = max(0, grid.nx - origin_col)
    if total <= 0:
        return 1, 0
    cwid = max(1, min(6, (width - 10) // total))
    n = min(total, max(1, (width - 10) // cwid))
    return cwid, n


def _chart_body(
    definition: Definition, cells: list, cwid: int, h: int, lo: float, hi: float,
) -> list[Text]:
    """The value-above line (when edited) and the ``h`` bar rows of a chart."""
    lines = []
    if any(edited for _, edited, _, _ in cells):
        head = Text(" " * _CHART_LABEL)
        for text, edited, bar, cur in cells:
            head.append_text(_fit(text, cwid, style=EDIT, align="left") if edited else Text(" " * cwid))
        lines.append(head)
    for i in range(h):
        if i == 0:
            row = _fit(display_text(definition, hi), _CHART_LABEL - 1, align="right")
        elif i == h - 1:
            row = _fit(display_text(definition, lo), _CHART_LABEL - 1, align="right")
        else:
            row = Text(" " * (_CHART_LABEL - 1))
        row.append(" ")
        for text, edited, bar, cur in cells:
            style = EDIT if edited else ""
            if edited and cur is not None and i == max(0, min(h - 1, h - 1 - cur // 8)):
                marker = "━" if bar is not None and cur <= bar else "─"
                row.append(marker * cwid, style=style)
            elif bar is None and i == h - 1:
                row.append("?" + " " * (cwid - 1))
            else:
                row.append(_block(bar, h, i) * cwid, style=style)
        lines.append(row)
    return lines


# --------------------------------------------------------------------------- public


def _shown(width: int, grid: Grid, origin: tuple[int, int], canvas_room: int) -> tuple[int, int]:
    """(rows shown, columns shown) of the canvas in ``canvas_room`` lines."""
    if grid.mode == "chart":
        return 1, chart_geometry(width, grid, origin[1])[1]
    return grid_rows_shown(canvas_room, grid)[0], grid_geometry(width, grid)[0]


def canvas_shape(width: int, grid: Grid, origin: tuple[int, int], room: int) -> tuple[int, int, int]:
    """(canvas room, rows shown, columns shown) of a bench in ``room`` detail lines: the definition line,
    the legend, the tool row and the bytes line take four lines, the window line one more while it shows."""
    canvas_room = max(0, room - 4)
    rows_shown, cols_shown = _shown(width, grid, origin, canvas_room)
    if window_line(grid, origin, rows_shown, cols_shown) is None:
        return canvas_room, rows_shown, cols_shown
    canvas_room = max(0, room - 5)
    return (canvas_room, *_shown(width, grid, origin, canvas_room))


def bench_detail(
    row: SheetRow, preview: Preview | None, width: int, state: BenchState | None, room: int,
) -> list[Text]:
    """The selected bench row's detail lines, cut to ``room`` and the sheet width."""
    if room < 1:
        return []
    definition_line = _FALLBACK_OPS.detail(row, None, width, None, 1)[0]
    if width < 12 or room == 1:
        return [Text(clip(definition_line.plain, width))]
    lines = [_cut(definition_line, width)]
    if state is not None and state.values is None and state.refusal is not None and state.job != "decode":
        lines.append(Text("✗ refused: " + plain(state.refusal.message)))
        return [_cut(line, width) for line in lines[: room]]
    if state is None or state.values is None or state.job == "decode":
        lines.append(Text(f"decoding {row.definition.element_count} values …"))
        return [_cut(line, width) for line in lines[: room]]
    grid = bench_grid(row.definition)
    canvas_room, rows_shown, cols_shown = canvas_shape(width, grid, state.origin, room)
    if grid.mode == "chart":
        canvas = chart_canvas(row.definition, grid, state.values, state.staged, state, width, canvas_room)
    else:
        canvas = grid_canvas(row.definition, grid, state.values, state.staged, state, width, canvas_room)
    lines.extend(canvas)
    window = window_line(grid, state.origin, rows_shown, cols_shown)
    if window is not None:
        lines.append(window)
    lines.append(legend_line(row.definition, grid, state.values, state))
    lines.append(tool_row(state.tool))
    lines.append(bytes_line(row.definition, state.runs, state.preview, width))
    return [_cut(line, width) for line in lines[: room]]


def grid_canvas(
    definition: Definition, grid: Grid, values: BenchValues, staged: BenchValues | None,
    state: BenchState, width: int, room: int,
) -> list[Text]:
    """The grid of CTX-PE-BENCH over the window: header, then value and bar rows."""
    if room < 1:
        return []
    nc, cw = grid_geometry(width, grid)
    rows_shown, two_rows = grid_rows_shown(room, grid)
    origin_row, origin_col = state.origin
    columns, row_labels = _canvas_labels(state, definition, grid)
    lo_c, hi_c = sorted((state.anchor[0], state.cursor[0]))
    lo_r, hi_r = sorted((state.anchor[1], state.cursor[1]))
    lines = [_grid_header(columns, origin_col, nc, cw)]
    for r in range(rows_shown):
        row = origin_row + r
        if row >= grid.ny:
            break
        value = _fit(row_labels[row] if row < len(row_labels) else "", 6, align="right")
        for k in range(nc):
            col = origin_col + k
            selected = lo_c <= col <= hi_c and lo_r <= row <= hi_r
            value.append_text(_grid_cell(definition, grid, values, staged, state, col, row, cw, selected, two_rows))
            if k < nc - 1:
                value.append(" ")
        lines.append(value)
        if two_rows:
            lines.append(_grid_bar_row(grid, origin_col, nc, cw, row, lo_c, hi_c, lo_r, hi_r))
    return lines[: room]


def chart_canvas(
    definition: Definition, grid: Grid, values: BenchValues, staged: BenchValues | None,
    state: BenchState, width: int, room: int,
) -> list[Text]:
    """The chart of CTX-PE-BENCH over the window of points, cut to ``room``."""
    if room < 1:
        return []
    h = max(1, min(16, room - 4))
    lo, hi = state.lo, state.hi
    origin_col = state.origin[1]
    cwid, n = chart_geometry(width, grid, origin_col)
    if n <= 0:
        return []
    columns, _ = _canvas_labels(state, definition, grid)
    cells = []
    for k in range(n):
        point = origin_col + k
        number, text, edited = _shown_value(definition, values, staged, state, (point,), point)
        bar = _eighths(number, lo, hi, h)
        cur = _eighths(values.numbers[point], lo, hi, h) if edited else None
        cells.append((text, edited, bar, cur))
    lines = _chart_body(definition, cells, cwid, h, lo, hi)
    tick = Text(" " * _CHART_LABEL)
    for k, (text, edited, bar, cur) in enumerate(cells):
        if k % 4 == 0:
            point = origin_col + k
            label = columns[point] if point < len(columns) else ""
            tick.append(f"{plain(label)} pt")
        else:
            tick.append(" " * cwid)
    lines.append(tick)
    return lines[: room]


def axis_labels(
    definition: Definition, axes: tuple[DecodedAxis, ...], grid: Grid,
) -> tuple[list[str], list[str]]:
    """The canvas's column and row labels of CTX-PE-BENCH, as plain text."""
    if definition.kind == "curve":
        x_axis = next((a for a in axes if a.letter == "X"), None)
        return _axis_point_labels(x_axis, "x", grid.nx), []
    if definition.kind == "map":
        x_axis = next((a for a in axes if a.letter == "X"), None)
        y_axis = next((a for a in axes if a.letter == "Y"), None)
        return _axis_point_labels(x_axis, "x", grid.nx), _axis_point_labels(y_axis, "y", grid.ny)
    if grid.layout == "flat":
        return [f"+{c}" for c in range(grid.nx)], [str(grid.nx * r) for r in range(grid.ny)]
    return [str(c) for c in range(grid.nx)], [str(r) for r in range(grid.ny)]


def legend_line(definition: Definition, grid: Grid, values: BenchValues, state: BenchState) -> Text:
    """The legend line of CTX-PE-BENCH under the canvas (lo/hi from the state)."""
    lo, hi = state.lo, state.hi
    unit = plain(definition.unit)
    line = Text()
    if grid.mode == "chart":
        line.append("scale ")
        line.append(short_number(lo - (hi - lo) / 10))
        line.append(" … ")
        line.append(short_number(hi))
        if unit:
            line.append(" " + unit)
        line.append("   ")
        line.append("█", style=EDIT)
        line.append(" edited  ─ old level")
    else:
        line.append("shade ")
        for step in range(12):
            line.append("█", style=ramp_style(step))
        line.append(" ")
        line.append(short_number(lo))
        line.append(" … ")
        line.append(short_number(hi))
        if unit:
            line.append(" " + unit)
        line.append(f"   sel {where_text(state, grid)[1:-1]}   * / bold = edited")
    return line


# --------------------------------------------------------------------------- U5


#: The tool row segments of CTX-PE-BENCH: (key, label); ``u`` is never selected.
_TOOL_ROW = (
    ("s", "Set"),
    ("d", "+Δ"),
    ("p", "×%"),
    ("i", "Interpolate"),
    ("m", "Smooth"),
    ("u", "Undo"),
)


def tool_row(tool: str) -> Text:
    """The tool row of CTX-PE-BENCH, the current tool's key and label reversed."""
    line = Text()
    for index, (key, label) in enumerate(_TOOL_ROW):
        if index:
            line.append("  ")
        line.append(f" {key}  {label}", style="reverse" if key == tool else "")
    line.append("    shift+arrows select")
    return line


def window_line(
    grid: Grid, origin: tuple[int, int], rows_shown: int, cols_shown: int,
) -> Text | None:
    """The window line of CTX-PE-BENCH, or ``None`` when every row and column shows."""
    origin_row, origin_col = origin
    if grid.mode == "chart":
        if origin_col == 0 and cols_shown >= grid.nx:
            return None
        last = min(origin_col + cols_shown, grid.nx) - 1
        return Text(f"points {origin_col}..{last} of {grid.nx} · pgup/pgdn page")
    all_shown = (
        origin_row == 0 and origin_col == 0 and rows_shown >= grid.ny and cols_shown >= grid.nx
    )
    if all_shown:
        return None
    row_last = min(origin_row + rows_shown, grid.ny) - 1
    col_last = min(origin_col + cols_shown, grid.nx) - 1
    return Text(
        f"rows {origin_row}..{row_last} of {grid.ny} · "
        f"cols {origin_col}..{col_last} of {grid.nx} · pgup/pgdn page"
    )


def bytes_line(
    definition: Definition,
    runs: tuple[tuple[int, bytes, bytes], ...],
    preview: object,
    width: int,
) -> Text:
    """The bytes line of CTX-PE-BENCH against the record over the staged overlay."""
    if preview is None:
        text = "no edit yet · bytes appear here"
    elif isinstance(preview, str):
        text = "encoding …"
    elif isinstance(preview, Refusal):
        text = "✗ refused: " + plain(preview.message)
    else:
        n = len(preview.data) if isinstance(preview, Encoded) else (definition.byte_length or 0)
        k = sum(len(old) for _, old, _ in runs)
        parts = [f"{k} of {n} B differ  "]
        for offset, old, new in runs[:64]:
            old_hex = " ".join(f"{b:02X}" for b in old)
            new_hex = " ".join(f"{b:02X}" for b in new)
            parts.append(f"+0x{offset:02X} {old_hex} → {new_hex}  ")
        text = "".join(parts)
    return Text(clip(text, width))


def op_line(row: SheetRow, state: BenchState, width: int) -> tuple[str, Text]:
    """The op line bar: the name with its ``<where>`` and the tail, cut to fit."""
    grid = bench_grid(row.definition)
    where = where_text(state, grid)
    name = name_echo(row.name)
    room = _NAME_CELLS - Text(where).cell_len
    if Text(name).cell_len > room:
        name = clip(name, max(1, room))
    name += where
    tail = Text()
    unit = plain(row.definition.unit)
    if unit:
        tail.append(unit)
        tail.append("  ")
    label = _TOOL_LABELS.get(state.tool, "Set")
    count = len(selection_cells(state, grid))
    tail.append(f"{label} on {count_text(count, 'pt' if grid.mode == 'chart' else 'cell')}")
    preview = state.preview
    if isinstance(preview, Encoded):
        tail.append(" ✓" if not preview.notices else f" ▲ {count_text(len(preview.notices), 'notice')}")
    elif isinstance(preview, Refusal):
        tail.append(" ✗ " + plain(preview.message))
    tail.append("   enter apply  alt+s stage record")
    return name, _cut(tail, width) if width > 0 else Text()


def busy_title(idle: str, word: str, name: str, seconds: float, frame: int, room: int) -> Text:
    """The staging window's busy title: ``idle``, two spaces, the busy pill; the name cut to fit ``room``."""
    head = f" {'◐◓◑◒'[frame % 4]} BUSY · {word} "
    tail = f" · {seconds:.1f} s · keys still work "
    room_for_name = max(1, room - len(idle) - 2 - len(head) - len(tail))
    echo = clip(name_echo(name), room_for_name)
    title = Text(idle + "  ")
    title.append(head + echo + tail, style=f"bold {DEPTH_BG} on {BUSY_COLOR}")
    return title
