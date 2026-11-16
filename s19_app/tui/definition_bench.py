"""The model of the Patch Editor's array, curve and map benches (Inc 9, group B1).

Pure module: the standard library, ``rich.text.Text`` and the I-2 types of
``a2l_definition`` only, no ``textual`` import. It builds the grid of a bench
definition, keeps the decoded values compact, holds each bench row's edit state
and moves its cursor and window. The lines that paint a bench live in
``definition_bench_view.py``; the sheet that keeps these states per row is
``patch_editor/bench_sheet.py``.

Unit U1 holds: ``Grid``, ``bench_grid``, ``BenchValues``, ``BenchState``,
``move_cursor``, ``page_cursor``, ``window_for``.
"""

from __future__ import annotations

import math
import re
from array import array
from dataclasses import dataclass, field, replace
from decimal import Decimal, ROUND_HALF_UP
from typing import Mapping

from rich.text import Text

from .a2l_definition import (
    Decoded,
    DecodedAxis,
    DecodedValues,
    Definition,
    Encoded,
    Refusal,
    display_text,
    element_name,
)
from .definition_sheet import (
    Preview,
    SheetRow,
    SheetWidths,
    StagedOverlay,
    kind_word,
    name_echo,
    plain,
    range_cell,
    short_number,
)
from .insight_style import DGRAY

#: A bench cell position: ``(c, r)`` for a 2-D grid, ``(16 * r + c,)`` for a
#: flat grid, ``(k,)`` for a chart (CTX-PE-BENCH *Position*).
Position = tuple[int, ...]


@dataclass(frozen=True)
class Grid:
    """The grid of a bench definition.

    ``mode`` is "chart" (one row of ``nx`` points) or "grid"; ``nx`` / ``ny``
    are the columns and rows; ``count`` is the element count; ``layout`` is
    "2d" (a map or 2-D array) or "flat" (a 1-D or >= 3-D array, 16 columns).
    """

    mode: str
    nx: int
    ny: int
    count: int
    layout: str


@dataclass(frozen=True)
class BenchValues:
    """The decoded values of a bench row, kept compact in element order.

    ``numbers`` holds every element's number as a double (``nan`` for a missing
    or text element); ``texts`` is the element texts, parallel to ``numbers``
    with ``""`` for a number element, only when some element is a text, else
    ``None``; ``missing`` is the indexes of the missing (refused) and text
    elements.
    """

    numbers: array
    texts: tuple[str, ...] | None
    missing: frozenset[int]

    @staticmethod
    def from_decoded(decoded: DecodedValues) -> BenchValues:
        """Copy I-2's ``DecodedValues`` into a ``BenchValues``, dropping the I-2
        objects: element-order numbers in an ``array("d")``; a refused element
        or a text element stores ``nan`` and its index joins ``missing``."""
        numbers = array("d")
        missing: set[int] = set()
        texts: list[str] = []
        has_text = False
        for index, element in enumerate(decoded.values):
            if isinstance(element, Decoded) and _is_number(element.value):
                numbers.append(float(element.value))
                texts.append("")
            else:
                numbers.append(float("nan"))
                missing.add(index)
                if isinstance(element, Decoded):
                    has_text = True
                    texts.append(element.text)
                else:
                    texts.append("")
        return BenchValues(numbers, tuple(texts) if has_text else None, frozenset(missing))


def _is_number(value: object) -> bool:
    """True when ``value`` is an ``int`` or ``float`` (not a ``bool``)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@dataclass(frozen=True)
class BenchState:
    """A bench row's edit state, kept by row name for its lifetime.

    ``cursor`` / ``anchor`` are (col, row) cells (a chart's cursor is
    (point, 0)); ``origin`` is (row, col); ``edit`` is position -> text.
    ``status`` carries a refusal's text (``apply_tool`` and ``undo`` set it on
    a copy and never return a bare string). ``refusal`` is the I-2 refusal of
    the row's values decode, set by the bench worker with ``values`` None
    (the Current cell shows ``--``, R-PE-BENCH.14). ``staged_delta``: see
    :func:`staged_delta` (FX9c O-D).
    """

    cursor: tuple[int, int] = (0, 0)
    anchor: tuple[int, int] = (0, 0)
    tool: str = "s"
    edit: Mapping[Position, str] = field(default_factory=dict)
    undo: tuple[Mapping[Position, str], ...] = ()
    origin: tuple[int, int] = (0, 0)
    focus: bool = False
    values: BenchValues | None = None
    staged: BenchValues | None = None
    axes: tuple[DecodedAxis, ...] = ()
    preview: Encoded | Refusal | None = None
    job: str | None = None
    runs: tuple[tuple[int, bytes, bytes], ...] = ()
    lo: float = 0.0
    hi: float = 0.0
    strip: Text | None = None
    labels: tuple[tuple[str, ...], tuple[str, ...]] | None = None
    status: str | None = None
    refusal: Refusal | None = None
    staged_delta: tuple[BenchValues, BenchValues, float | None] | None = field(default=None, compare=False, repr=False)


def bench_grid(definition: Definition) -> Grid:
    """The grid of a bench definition: a curve -> a chart of ``shape[0]``
    points; a map or 2-D array -> ``nx`` x ``ny`` ("2d"); a 1-D or >= 3-D array
    -> 16 columns, ``ceil(count / 16)`` rows ("flat")."""
    shape = definition.shape
    count = definition.element_count
    if count is None:
        count = 1
        for size in shape:
            count *= size
    if definition.kind == "curve":
        return Grid("chart", shape[0], 1, shape[0], "2d")
    if len(shape) == 2:
        return Grid("grid", shape[0], shape[1], count, "2d")
    return Grid("grid", 16, math.ceil(count / 16), count, "flat")


def _row_width(grid: Grid, row: int) -> int:
    """The number of cells in ``row`` (a flat grid's last row may be short)."""
    if grid.layout == "flat":
        return min(grid.nx, max(0, grid.count - grid.nx * row))
    return grid.nx


def move_cursor(state: BenchState, grid: Grid, dx: int, dy: int, extend: bool) -> BenchState:
    """Move the cursor one cell within the grid (no wrap); ``extend`` keeps the
    anchor, else the anchor follows the cursor.  The origin is left unchanged
    (the sheet calls ``window_for`` with the real shown sizes)."""
    col, row = state.cursor
    new_row = min(max(row + dy, 0), grid.ny - 1)
    new_col = min(max(col + dx, 0), _row_width(grid, new_row) - 1)
    anchor = state.anchor if extend else (new_col, new_row)
    return replace(state, cursor=(new_col, new_row), anchor=anchor)


def page_cursor(state: BenchState, grid: Grid, rows: int, direction: int) -> BenchState:
    """Move the cursor ``rows`` rows (clamped), anchor follows, origin unchanged."""
    col, row = state.cursor
    new_row = min(max(row + rows * direction, 0), grid.ny - 1)
    new_col = min(col, _row_width(grid, new_row) - 1)
    return replace(state, cursor=(new_col, new_row), anchor=(new_col, new_row))


def window_for(state: BenchState, grid: Grid, rows_shown: int, cols_shown: int) -> tuple[int, int]:
    """The least move of the origin that keeps the cursor inside the shown rows
    and columns; fewer than 1 shown row or column counts as 1."""
    rows_shown = max(1, rows_shown)
    cols_shown = max(1, cols_shown)
    origin_row, origin_col = state.origin
    col, row = state.cursor
    if row < origin_row:
        origin_row = row
    elif row >= origin_row + rows_shown:
        origin_row = row - rows_shown + 1
    if col < origin_col:
        origin_col = col
    elif col >= origin_col + cols_shown:
        origin_col = col - cols_shown + 1
    return origin_row, origin_col


# --------------------------------------------------------------------------- U2


#: The tool labels of CTX-PE-BENCH, by key letter.
_TOOL_LABELS = {"s": "Set", "d": "+Δ", "p": "×%", "i": "Interpolate", "m": "Smooth"}

#: The float datatypes (a result rounds to an integer only for a non-float
#: datatype whose conversion is none or IDENTICAL).
_FLOAT_DATATYPES = frozenset({"FLOAT16_IEEE", "FLOAT32_IEEE", "FLOAT64_IEEE"})

#: The operand *number text* grammar (the surrounding spaces are ``strip``ped).
_OPERAND_RE = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")

#: The undo stack holds at most this many edits.
_UNDO_MAX = 32


def _position_of(grid: Grid, r: int, c: int) -> tuple:
    """The I-2 position of grid cell (col ``c``, row ``r``)."""
    if grid.mode == "chart":
        return (c,)
    if grid.layout == "2d":
        return (c, r)
    return (grid.nx * r + c,)


def _element_index(grid: Grid, position: tuple) -> int:
    """The element-order index of an I-2 position."""
    if grid.mode == "grid" and grid.layout == "2d":
        c, r = position
        return c + grid.nx * r
    return position[0]


def _current_text(definition: Definition, values: BenchValues, index: int) -> str:
    """The shown value text of element ``index`` (the Set no-op comparison)."""
    if index in values.missing:
        text = values.texts[index] if values.texts is not None else ""
        return text if text else "--"
    return display_text(definition, values.numbers[index])


def _refuse(state: BenchState, message: str) -> BenchState:
    """The same state with ``status`` set (an apply/undo refusal)."""
    return replace(state, status=f"Patch Editor: {message}")


def _finish_apply(state: BenchState, new_edit: Mapping[Position, str]) -> BenchState:
    """The state with ``new_edit`` applied, the old edit pushed on undo (≤ 32)."""
    undo = (state.undo + (state.edit,))[-_UNDO_MAX:]
    return replace(state, edit=new_edit, undo=undo, status=None)


def _tool_results(
    tool: str,
    grid: Grid,
    values: BenchValues,
    operand_number: float | None,
    state: BenchState,
) -> dict:
    """The tool's number for each cell it changes, in element order."""
    lo_c, hi_c = sorted((state.anchor[0], state.cursor[0]))
    lo_r, hi_r = sorted((state.anchor[1], state.cursor[1]))
    results: dict = {}
    if tool in ("d", "p"):
        factor = 1 + operand_number / 100 if tool == "p" else 1.0
        for r in range(lo_r, hi_r + 1):
            for c in range(lo_c, min(hi_c, _row_width(grid, r) - 1) + 1):
                v = values.numbers[c + grid.nx * r]
                number = v * factor if tool == "p" else v + operand_number
                results[_position_of(grid, r, c)] = number
    elif tool == "i":
        span = hi_c - lo_c
        for r in range(lo_r, hi_r + 1):
            if hi_c >= _row_width(grid, r):
                continue
            v0 = values.numbers[lo_c + grid.nx * r]
            v1 = values.numbers[hi_c + grid.nx * r]
            for c in range(lo_c + 1, hi_c):
                number = v0 + (v1 - v0) * (c - lo_c) / span
                results[_position_of(grid, r, c)] = number
    elif tool == "m":
        for r in range(lo_r, hi_r + 1):
            if hi_c >= _row_width(grid, r):
                continue
            for c in range(lo_c + 1, hi_c):
                number = (
                    values.numbers[c - 1 + grid.nx * r]
                    + values.numbers[c + grid.nx * r]
                    + values.numbers[c + 1 + grid.nx * r]
                ) / 3
                results[_position_of(grid, r, c)] = number
    return results


def selection_cells(state: BenchState, grid: Grid) -> list[tuple]:
    """The I-2 positions of the rectangle cursor..anchor in element order; a flat
    grid's cells past the element count are left out (R-PE-BENCH.52 … .56)."""
    lo_c, hi_c = sorted((state.anchor[0], state.cursor[0]))
    lo_r, hi_r = sorted((state.anchor[1], state.cursor[1]))
    cells: list[tuple] = []
    for r in range(lo_r, hi_r + 1):
        for c in range(lo_c, hi_c + 1):
            if grid.layout == "flat" and grid.nx * r + c >= grid.count:
                continue
            cells.append(_position_of(grid, r, c))
    return cells


def where_text(state: BenchState, grid: Grid) -> str:
    """The where of CTX-PE-BENCH (R-PE-BENCH.42, .50)."""
    if grid.mode == "chart":
        a, b = sorted((state.anchor[0], state.cursor[0]))
        return f"[{a}..{b}]" if a != b else f"[{a}]"
    if grid.layout == "2d":
        c0, c1 = sorted((state.anchor[0], state.cursor[0]))
        r0, r1 = sorted((state.anchor[1], state.cursor[1]))
        x = f"x{c0}" if c0 == c1 else f"x{c0}..{c1}"
        y = f"y{r0}" if r0 == r1 else f"y{r0}..{r1}"
        return f"[{x},{y}]"
    cells = selection_cells(state, grid)
    a, b = cells[0][0], cells[-1][0]
    return f"[{a}..{b}]" if a != b else f"[{a}]"


def parse_operand(text: str) -> float | None:
    """The operand's number: spaces around the *number text* grammar; ``None``
    when the text does not match or its double is not finite (R-PE-BENCH.62)."""
    body = text.strip()
    if not _OPERAND_RE.fullmatch(body):
        return None
    value = float(body)
    return value if math.isfinite(value) else None


def result_text(definition: Definition, value: float) -> str:
    """15 significant digits, then half away from zero to d decimals: 0 for an
    integer datatype with no conversion or IDENTICAL, else the definition's
    decimals; no decimals → the 15-digit text (R-PE-BENCH.57)."""
    decimals = definition.decimals
    if decimals is None:
        return f"{value:.15g}"
    datatype = definition.datatype
    conversion = definition.conversion_type
    if (
        datatype is not None
        and datatype not in _FLOAT_DATATYPES
        and conversion in (None, "IDENTICAL")
    ):
        decimals = 0
    quantized = Decimal(f"{value:.15g}").quantize(
        Decimal(1).scaleb(-decimals), rounding=ROUND_HALF_UP
    )
    return str(int(quantized)) if decimals == 0 else format(quantized, f".{decimals}f")


def undo(state: BenchState) -> BenchState:
    """Restore the newest undo entry; an empty stack keeps the edit and sets the
    nothing-to-undo status (R-PE-BENCH.59, .61)."""
    if not state.undo:
        return replace(state, status="Patch Editor: nothing to undo on the bench.")
    return replace(state, edit=state.undo[-1], undo=state.undo[:-1], status=None)


def _set_edit(definition: Definition, state: BenchState, grid: Grid, values: BenchValues, operand: str) -> BenchState:
    """Set: the operand text for every selected cell whose shown text differs."""
    new_edit: dict[Position, str] = {}
    for position in selection_cells(state, grid):
        index = _element_index(grid, position)
        if operand != _current_text(definition, values, index):
            new_edit[position] = operand
    return _finish_apply(state, new_edit)


def _precheck(definition, state, grid, values, operand) -> tuple[float | None, str | None]:
    """The operand number and None, or None and the refusal message."""
    label = _TOOL_LABELS.get(state.tool, "Set")
    if values.texts is not None:
        return None, f"{label} needs numbers — {name_echo(definition.name)} holds texts."
    operand_number: float | None = None
    if state.tool in ("d", "p"):
        operand_number = parse_operand(operand)
        if operand_number is None:
            return None, f"'{name_echo(operand)}' is not a number."
    columns = abs(state.cursor[0] - state.anchor[0])
    if state.tool == "i" and columns == 0:
        return None, f"{label} needs at least 2 columns in the selection."
    if state.tool == "m" and columns < 2:
        return None, f"{label} needs at least 3 columns in the selection."
    for position in selection_cells(state, grid):
        index = _element_index(grid, position)
        if index in values.missing or not math.isfinite(values.numbers[index]):
            return None, f"{element_name(definition, position)} has no value to change."
    return operand_number, None


def apply_tool(
    definition: Definition,
    state: BenchState,
    grid: Grid,
    values: BenchValues,
    operand: str,
) -> BenchState:
    """The current tool's results over the selection, each number through
    ``result_text``; cells whose result equals the current value leave the edit
    and the old edit is pushed on undo (≤ 32).  A refusal returns the same state
    with ``status`` set (R-PE-BENCH.51 … .58, .62 … .67)."""
    if state.tool == "s":
        return _set_edit(definition, state, grid, values, operand)
    operand_number, message = _precheck(definition, state, grid, values, operand)
    if message is not None:
        return _refuse(state, message)
    new_edit: dict[Position, str] = {}
    for position, number in _tool_results(state.tool, grid, values, operand_number, state).items():
        if not math.isfinite(number):
            label = _TOOL_LABELS.get(state.tool, "Set")
            name = element_name(definition, position)
            return _refuse(state, f"{label} gives a value that is not finite for {name}.")
        if number != values.numbers[_element_index(grid, position)]:
            new_edit[position] = result_text(definition, number)
    return _finish_apply(state, new_edit)


# --------------------------------------------------------------------------- U3


#: The seven levels of a summary strip, level 1..7 -> index 0..6. Never the
#: full-height block: it joins the cell above and below in a terminal
#: (F-R14-1, R-PE-BENCH.107).
_BLOCKS = "▁▂▃▄▅▆▇"

#: The ramp background endpoints (step 0 -> step 11) of CTX-PE-BENCH.
_RAMP_LO = (0x1C, 0x24, 0x38)
_RAMP_HI = (0x91, 0xAB, 0xEC)


def finite_range(numbers, missing) -> tuple[float, float]:
    """The least and greatest finite value of ``numbers``, skipping the indexes
    in ``missing`` and non-finite values; (0.0, 0.0) with none."""
    lo = math.inf
    hi = -math.inf
    for index, value in enumerate(numbers):
        if index in missing or not math.isfinite(value):
            continue
        if value < lo:
            lo = value
        if value > hi:
            hi = value
    if lo == math.inf:
        return 0.0, 0.0
    return lo, hi


def ramp_step(v: float, lo: float, hi: float) -> int:
    """The 12-step ramp step of ``v`` over ``[lo, hi]``: round(t × 11) clamped
    to 0..11; t is 0 when lo == hi (no division)."""
    if lo == hi:
        return 0
    t = (v - lo) / (hi - lo)
    return min(11, max(0, round(t * 11)))


def ramp_style(step: int) -> str:
    """The rich style of a ramp step: the background interpolated linearly
    between #1c2438 (step 0) and #91abec (step 11), white foreground below
    step 6, dark above."""
    t = step / 11
    lo_r, lo_g, lo_b = _RAMP_LO
    hi_r, hi_g, hi_b = _RAMP_HI
    r = round(lo_r + (hi_r - lo_r) * t)
    g = round(lo_g + (hi_g - lo_g) * t)
    b = round(lo_b + (hi_b - lo_b) * t)
    fg = "#ffffff" if step < 6 else "#101828"
    return f"{fg} on #{r:02X}{g:02X}{b:02X}"


def bench_mark(row: SheetRow, state: BenchState | None) -> str:
    """The mark glyph: ◆ while the edit is not empty, ● while staged, else a
    space (never read from the formula text, R-PE-BENCH.18)."""
    if state is not None and state.edit:
        return "◆"
    if row.is_staged:
        return "●"
    return " "


def summary_strip(values: BenchValues, grid: Grid, width: int) -> Text:
    """A one-line summary of the values, at most ``width`` cells: one of seven
    blocks (never the full-height one) per k-th point (k = ceil(n/width)) of a
    chart, or per k-th column of a grid at the level of its finite mean; lo/hi
    over the finite values only (a non-finite point or an all-missing column is
    a space). Painted in DGRAY with no ground of its own (R-PE-BENCH.107/.108)."""
    if width <= 0:
        return Text()
    lo, hi = finite_range(values.numbers, values.missing)
    line = Text()
    if grid.mode == "chart":
        k = max(1, math.ceil(grid.nx / width))
        for point in range(0, grid.nx, k):
            value = values.numbers[point]
            if point in values.missing or not math.isfinite(value):
                line.append(" ")
                continue
            t = 0.0 if lo == hi else (value - lo) / (hi - lo)
            line.append(_BLOCKS[round(t * 6)], style=DGRAY)
        return line
    k = max(1, math.ceil(grid.nx / width))
    for column in range(0, grid.nx, k):
        total = 0.0
        count = 0
        for row in range(grid.ny):
            index = column + grid.nx * row
            if index >= grid.count:
                continue
            value = values.numbers[index]
            if index in values.missing or not math.isfinite(value):
                continue
            total += value
            count += 1
        if count == 0:
            line.append(" ")
            continue
        t = 0.0 if lo == hi else (total / count - lo) / (hi - lo)
        line.append(_BLOCKS[round(t * 6)], style=DGRAY)
    return line


def _max_delta(values: BenchValues, edit: Mapping[Position, str], grid: Grid) -> float | None:
    """The largest |shown - current| over the edit cells whose current value is
    finite and whose edit text parses as a float; None with no such pair."""
    best: float | None = None
    for position, text in edit.items():
        index = _element_index(grid, position)
        current = values.numbers[index]
        if not math.isfinite(current):
            continue
        try:
            shown = float(text)
        except (TypeError, ValueError):
            continue
        delta = abs(shown - current)
        if best is None or delta > best:
            best = delta
    return best


def _max_staged_delta(values: BenchValues, staged: BenchValues) -> float | None:
    """The largest |staged - current| over all finite pairs; None with none."""
    best: float | None = None
    for current, staged_value in zip(values.numbers, staged.numbers):
        if not (math.isfinite(current) and math.isfinite(staged_value)):
            continue
        delta = abs(staged_value - current)
        if best is None or delta > best:
            best = delta
    return best


def staged_delta(values: BenchValues, staged: BenchValues) -> tuple[BenchValues, BenchValues, float | None]:
    """``BenchState.staged_delta``: computed by the bench worker, used by the Δ cell while the state's ``values``
    and ``staged`` are these same objects."""
    return values, staged, _max_staged_delta(values, staged)


def _changed_cells(definition: Definition, state: BenchState, grid: Grid) -> dict[Position, str]:
    """The edit cells whose shown value text differs from the current one
    (the k of the New and Δ cells, CTX-PE-BENCH array row cells)."""
    if state.values is None:
        return dict(state.edit)
    return {
        position: text
        for position, text in state.edit.items()
        if text != _current_text(definition, state.values, _element_index(grid, position))
    }


def _delta_text(row: SheetRow, state: BenchState | None, grid: Grid) -> Text:
    """The Δ cell: ✗ refused, max |Δ| over the edit, or max |Δ| staged."""
    if state is None:
        return Text("")
    if isinstance(state.preview, Refusal):
        return Text("✗ refused")
    if state.edit:
        if state.values is None:
            return Text("max |Δ| -")
        best = _max_delta(state.values, _changed_cells(row.definition, state, grid), grid)
        return Text("max |Δ| -" if best is None else f"max |Δ| {short_number(best)}")
    if row.is_staged and state.staged is not None and state.values is not None:
        cached = state.staged_delta
        if cached is not None and cached[0] is state.values and cached[1] is state.staged:
            best = cached[2]
        else:
            best = _max_staged_delta(state.values, state.staged)
        return Text("max |Δ| - staged" if best is None else f"max |Δ| {short_number(best)} staged")
    return Text("")


def count_text(n: int, word: str) -> str:
    """``n`` and ``word``, the word plural unless ``n`` is 1 (`1 cell`, `2 cells`)."""
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def bench_cells(
    row: SheetRow, state: BenchState | None, widths: SheetWidths
) -> tuple[Text, Text, Text, Text, Text]:
    """The array row cells (Kind, Current, New, Limits, Δ) of CTX-PE-BENCH; Limits
    is the range form of CTX-PE-DEF (``range_cell``)."""
    definition = row.definition
    grid = bench_grid(definition)
    count = grid.count

    kind = plain(kind_word(definition))
    if definition.kind == "map":
        kind = f"{kind} {grid.nx}x{grid.ny}"

    if state is not None and state.values is not None:
        strip = state.strip if state.strip is not None else Text()
        current = strip.copy()
        current.append(f" {count}")
    elif state is not None and state.job in ("summary", "decode"):
        current = Text(f"… {count}")
    elif state is not None and state.refusal is not None:
        current = Text("--")
    else:
        current = Text(f"{count} values")

    changed = len(_changed_cells(definition, state, grid)) if state is not None else 0
    new = Text(count_text(changed, "pt" if grid.mode == "chart" else "cell") if changed else "·")

    limits_text = range_cell(definition.limits.lower, definition.limits.upper)

    return Text(kind), current, new, limits_text, _delta_text(row, state, grid)


def bench_preview(
    definition: Definition, a2l_data: dict, text: str, overlay: StagedOverlay
) -> Preview:
    """The bench never previews on a keystroke: a Preview with no result (the
    preview job runs off the thread after an apply, R-PE-BENCH.66)."""
    return Preview(result=None, decoded=None)
