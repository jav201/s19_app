"""The model of the Patch Editor's staging sheet (batch-103 Inc 8, group S1).

Pure module: rich ``Text`` and the I-2 functions of ``a2l_definition`` only, no
toolkit import at import time. It builds the sheet's rows from definitions, the
cell texts of every row, the detail under the selected row and the formula bar's
fill and tail. The widget that paints them is ``patch_editor/sheet.py``.

Interfaces: I-8.1 ``StagedOverlay`` and I-8.5 ``KindOps`` / ``_KIND_OPS`` /
``ops_for`` (Inc 9 adds keys to ``_KIND_OPS``; nothing else here is theirs).
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from math import isfinite
from typing import Callable, NamedTuple, Optional

from rich.cells import cell_len
from rich.text import Text

from .a2l_definition import (
    Decoded,
    Definition,
    Encoded,
    Refusal,
    decode_definition,
    encode_definition,
)
from .insight_style import (
    DEPTH_BG,
    DEPTH_BORDER,
    DEPTH_ODD_ROW,
    DEPTH_PANEL,
    DGRAY,
    GREEN,
    HILITE,
    PURPLE,
    RED,
    VALUE,
    YELLOW,
)

# The sheet styles of CTX-PE-DEF (Inc 8b): one name per element.
_TEXT = VALUE
_DIM = DGRAY
_RULE = HILITE
_STAGED = GREEN
_PENDING = PURPLE
_REFUSED = RED
_NOTICE = YELLOW
_SELECTED_GROUND = "#1c2547"
_ODD_GROUND = DEPTH_ODD_ROW
_EXPANDED_GROUND = DEPTH_BORDER
_CARD_GROUND = DEPTH_PANEL
_KEY_INK = DEPTH_BG
_STAGED_STYLE = f"bold {_STAGED}"
_PENDING_STYLE = f"bold {_PENDING}"
_REFUSED_STYLE = f"bold {_REFUSED}"
_CHANGED_STYLE = f"{_PENDING_STYLE} underline"

GRID_WIDTH = 143  # the mark's 2 cells + Σ(column width + 1 gutter)
_LIMITS_WIDTH = 34
_SLOT = 7  # a limit slot: 6 cells of number, 1 cell of unit letter
_TRACK = _LIMITS_WIDTH - 2 * _SLOT - 2  # 18
_MIDDLE = (_TRACK - 1) // 2  # the range mark's cell inside the track
_ELLIPSIS = "…"
_FFFD = "�"
_ECHO_LIMIT = 256
_TEXT_EDIT_MAX = 4096  # a text row has an editor while its span is at most this
_TEXT_ROWS_BYTES = 64  # text rows show the span's first 64 bytes
_FILL_MAX = 4096
_CONTROLS = re.compile("[\x00-\x1f\x7f-\x9f]")

# Duplicated from a2l_parameter_picker._DATATYPE_FORMATS (that module imports the toolkit).
_DATATYPE_FORMATS = {
    "UBYTE": "u8", "BYTE": "u8", "SBYTE": "s8", "UWORD": "u16", "WORD": "u16",
    "SWORD": "s16", "ULONG": "u32", "LONG": "u32", "SLONG": "s32",
    "A_UINT64": "u64", "A_INT64": "s64", "FLOAT16_IEEE": "f16",
    "FLOAT32_IEEE": "f32", "FLOAT64_IEEE": "f64",
}


# --------------------------------------------------------------------------- plain text


def plain(text: str) -> str:
    """Replace every control character (U+0000..1F, U+007F..9F) by U+FFFD."""
    return _CONTROLS.sub(_FFFD, text)


def name_echo(text: str) -> str:
    """At most the first 256 characters, controls cleaned, then ``…`` when longer."""
    head = plain(text[:_ECHO_LIMIT])
    return head + _ELLIPSIS if len(text) > _ECHO_LIMIT else head


def clip(text: str, width: int, clean: bool = False) -> str:
    """Fit ``text`` in ``width`` cells: the longest start that fits in width-1 cells, then ``…``.

    ``clean`` also replaces control characters; the scan reads a bounded prefix, so a
    huge text is never walked (nor cleaned) whole.
    """
    if width <= 0:
        return ""
    bound = width * 4 + 16
    cut = len(text) > bound
    head = text[:bound] if cut else text
    if clean:
        head = plain(head)
    total = keep = 0
    for index, char in enumerate(head):
        total += cell_len(char)
        if total <= width - 1:
            keep = index + 1
        if total > width:
            return head[:keep] + _ELLIPSIS
    return head[:keep] + _ELLIPSIS if cut else head


def _fit(cell: Text, width: int) -> Text:
    """Truncate (with ``…``) or pad a Text to exactly ``width`` cells."""
    if cell.cell_len > width:
        cell.truncate(width, overflow="ellipsis", pad=True)
    else:
        cell.pad_right(width - cell.cell_len)
    return cell


def _text_cell(text: str, width: int, style: str = "") -> Text:
    return _fit(Text(clip(text, width, clean=True), style=style), width)


def _trim(line: Text, width: int) -> Text:
    if line.cell_len <= width:
        return line
    line = line.copy()
    line.truncate(width, overflow="ellipsis")
    return line


# --------------------------------------------------------------------------- widths


class SheetWidths(NamedTuple):
    mark: int
    name: int
    kind: int
    current: int
    new: int
    unit: int
    limits: int
    delta: int


_GRID_WIDTHS = SheetWidths(2, 26, 10, 20, 16, 8, _LIMITS_WIDTH, 20)


def sheet_widths(width: int) -> SheetWidths:
    """The grid widths of CTX-PE-DEF, whatever the view width.

    ``width`` is not used (the grid does not stretch); kept so the call shape of the
    callers holds.
    """
    return _GRID_WIDTHS


def _columns(widths: SheetWidths) -> tuple:
    return (
        ("Parameter", widths.name), ("Kind", widths.kind), ("Current", widths.current),
        ("New", widths.new), ("Unit", widths.unit), ("Limits", widths.limits),
        ("Δ", widths.delta),
    )


def header_line(widths: SheetWidths) -> Text:
    """The header: two spaces, then each label padded to its column and the gutter ``│``."""
    line = Text(" " * widths.mark)
    for label, width in _columns(widths):
        line.append_text(_fit(Text(clip(label, width), style=f"bold {_DIM}"), width))
        line.append("│", style=_RULE)
    return line


def header_rule(widths: SheetWidths) -> Text:
    """The rule under the header: ``━`` over the mark and each column, ``┿`` at each gutter."""
    line = Text("━" * widths.mark, style=_RULE)
    for _label, width in _columns(widths):
        line.append("━" * width + "┿", style=_RULE)
    return line


# --------------------------------------------------------------------------- I-8.1


class StagedOverlay(Mapping):
    """The image with the document entries' bytes written over it, in document order.

    ``__getitem__(address)``: the last entry byte written at ``address``, else
    ``image[address]``; ``KeyError`` when neither holds it. ``image`` None: only the
    entries' bytes. Read only; the image is never copied.
    """

    def __init__(
        self,
        image: Optional[Mapping[int, int]],
        entries: Sequence[tuple[int, Sequence[int]]],
    ) -> None:
        self._image = image
        written: dict[int, int] = {}
        for address, data in entries:
            for offset, byte in enumerate(data):
                written[address + offset] = int(byte)
        self._written = written

    def __getitem__(self, address: int) -> int:
        if address in self._written:
            return self._written[address]
        if self._image is not None:
            return self._image[address]
        raise KeyError(address)

    def __contains__(self, address: object) -> bool:
        if address in self._written:
            return True
        return self._image is not None and address in self._image

    def __iter__(self) -> Iterator[int]:
        if self._image is not None:
            yield from self._image
        for address in self._written:
            if self._image is None or address not in self._image:
                yield address

    def __len__(self) -> int:
        extra = sum(1 for a in self._written if self._image is None or a not in self._image)
        return extra + (len(self._image) if self._image is not None else 0)

    def written_in(self, start: int, end: int) -> Iterator[tuple[int, int]]:
        """The (address, byte) pairs of the entries that fall in ``start <= address < end``."""
        for address, byte in self._written.items():
            if start <= address < end:
                yield address, byte


# --------------------------------------------------------------------------- rows


@dataclass(frozen=True)
class SheetRow:
    """One sheet row: the definition, its current and staged decodes, its staged state.

    ``image`` and ``overlay`` are the sources the row was built over; the detail and the
    formula tail read the span's bytes from them on demand, never ``build_row``.
    """

    name: str
    definition: Definition
    kind: str
    current: object
    staged: object
    is_staged: bool = False
    image: Optional[Mapping[int, int]] = field(default=None, compare=False, repr=False)
    overlay: Optional[Mapping[int, int]] = field(default=None, compare=False, repr=False)


@dataclass(frozen=True)
class Preview:
    """I-2 encode of a pending text (an ``Encoded`` or a ``Refusal``) and its decode."""

    result: object
    decoded: object


def row_kind(definition: Definition) -> str:
    """number, bit mask, enum, text; ``none`` when refused; else I-2's kind word."""
    if definition.refusal is not None:
        return "none"
    if definition.kind == "number" and definition.bit_mask is not None:
        return "bit mask"
    return definition.kind or ""


def kind_word(definition: Definition) -> str:
    """The char type; ``MEASUREMENT`` for a measurement; ``?`` for neither."""
    if definition.section == "MEASUREMENT":
        return "MEASUREMENT"
    return definition.char_type or "?"


def _text_editable(definition: Definition) -> bool:
    length = definition.byte_length
    return length is not None and length <= _TEXT_EDIT_MAX


# --------------------------------------------------------------------------- numbers


def short_number(x: float) -> str:
    """|x| < 1000: one decimal, a trailing .0 dropped; else 3 significant digits + k/M/G."""
    if x != x or x in (float("inf"), float("-inf")):
        return str(x)
    if abs(x) < 1000:
        r = round(x, 1)
        return str(int(r)) if float(r).is_integer() else str(r)
    units = ((1e3, "k"), (1e6, "M"), (1e9, "G"))
    for index, (div, suffix) in enumerate(units):
        mantissa = abs(x) / div
        decimals = 2 if mantissa < 9.995 else 1 if mantissa < 99.95 else 0
        text = f"{x / div:.{decimals}f}"
        if abs(float(text)) < 1000:
            return text + suffix
        if index + 1 == len(units):
            return f"{x / div:.2e}{suffix}"
    raise AssertionError("unreachable")


def _signed(text: str) -> str:
    return text if text.startswith("-") else "+" + text


def _general(x: float) -> str:
    return str(int(x)) if float(x).is_integer() else f"{x:.10g}"


def _stored_text(decoded: object) -> str:
    if isinstance(decoded, Decoded) and isinstance(decoded.stored, (int, float)):
        return _general(decoded.stored)
    return "--"


def _numeric(value: object) -> Optional[float]:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


# --------------------------------------------------------------------------- byte reads


def _read(source: Optional[Mapping[int, int]], address: Optional[int], count: int) -> tuple:
    """``count`` bytes from ``address`` (None for a byte the source lacks)."""
    if source is None or address is None:
        return (None,) * count
    return tuple(source.get(address + i) for i in range(count))


def _hex(data: Sequence[Optional[int]]) -> str:
    return " ".join("--" if b is None else f"{b & 0xFF:02X}" for b in data)


def _hex_first8(data: Sequence[Optional[int]], span: int) -> str:
    return _hex(data[:8]) + (" " + _ELLIPSIS if span > 8 else "")


def _after_bytes(row: SheetRow, preview: Optional[Preview], count: int) -> tuple:
    if preview is not None and isinstance(preview.result, Encoded):
        data = tuple(preview.result.data[:count])
        return data + (None,) * (count - len(data))
    return _read(row.overlay, row.definition.address, count)


# --------------------------------------------------------------------------- per-kind ops


def _decode_scalar(definition, a2l_data, image):
    return decode_definition(definition, a2l_data or {}, image if image is not None else {})


def _decode_text(definition, a2l_data, image):
    return _decode_scalar(definition, a2l_data, image) if _text_editable(definition) else None


def _decode_none(definition, a2l_data, image):
    return None


def _missing(row: SheetRow, decoded: object) -> Optional[str]:
    # A refused definition never gets here: row_kind gives it "none", whose fallback says `refused`.
    return None if isinstance(decoded, Decoded) else "--"


def _value_number(row: SheetRow, decoded: object) -> str:
    gap = _missing(row, decoded)
    return gap if gap is not None else decoded.text


def _value_enum(row: SheetRow, decoded: object) -> str:
    gap = _missing(row, decoded)
    if gap is not None:
        return gap
    if decoded.value is not None:
        return f"{_stored_text(decoded)} {decoded.value}"
    return decoded.text


def _value_mask(row: SheetRow, decoded: object) -> str:
    gap = _missing(row, decoded)
    if gap is not None:
        return gap
    field_value = _numeric(decoded.stored)
    if field_value is None:
        return decoded.text
    return f"{int(field_value)} (0x{int(field_value):02X})"


def _value_text(row: SheetRow, decoded: object) -> str:
    if decoded is None and row.definition.refusal is None:
        return f"{row.definition.byte_length} B"
    gap = _missing(row, decoded)
    return gap if gap is not None else f'"{decoded.text}"'


def _value_fallback(row: SheetRow, decoded: object) -> str:
    if row.definition.refusal is not None:
        return "refused"
    count = row.definition.element_count
    return "--" if count is None else f"{count} values"


def _staged_by_text(row: SheetRow, image, overlay) -> bool:
    ops = ops_for(row.kind)
    return ops.value_text(row, row.current) != ops.value_text(row, row.staged)


def _staged_by_bytes(row: SheetRow, image, overlay) -> bool:
    """One pass over the document entries' bytes inside the span, each against the image."""
    definition = row.definition
    if definition.address is None or not definition.byte_length:
        return False
    end = definition.address + definition.byte_length
    changed = False
    for address, byte in overlay.written_in(definition.address, end):
        if image is None:
            changed = True
            continue
        try:
            changed |= image[address] != byte
        except KeyError:
            changed = True
    return changed


def _staged_text(row: SheetRow, image, overlay) -> bool:
    if _text_editable(row.definition):
        return _staged_by_text(row, image, overlay)
    return _staged_by_bytes(row, image, overlay)


def preview(definition: Definition, a2l_data: Optional[dict], text: str, overlay) -> Preview:
    """I-2 encode of ``text`` over the overlay and, for an ``Encoded``, the decode over it."""
    data = a2l_data or {}
    result = encode_definition(definition, data, text, overlay)
    if isinstance(result, Refusal):
        return Preview(result, None)
    after = StagedOverlay(overlay, ((result.address, result.data),))
    return Preview(result, decode_definition(definition, data, after))


def _no_preview(definition, a2l_data, text, overlay) -> Preview:
    return Preview(Refusal("SHEET-NO-EDITOR", "this row has no editor"), None)


def _submit_stage(name: str, text: str):
    """The stage request of the formula bar (lazy import: this module stays toolkit-free)."""
    from .screens_directionb.patch_editor.sheet import StagingSheet

    return StagingSheet.StageRequested(name, text)


def _no_submit(name: str, text: str):
    raise ValueError(f"{name}: a row with no editor cannot be staged")


# --------------------------------------------------------------------------- detail lines


def _coef(x: float) -> str:
    return format(x, ".10g")


def _mask_shift(mask: int) -> int:
    return (mask & -mask).bit_length() - 1


def _mask_text(definition: Definition) -> str:
    digits = max(2, 2 * (definition.byte_length or 1))
    return f"0x{definition.bit_mask:0{digits}X}"


def _formula(definition: Definition) -> str:
    raw = "raw"
    if definition.bit_mask is not None:
        raw = f"(word & {_mask_text(definition)}) >> {_mask_shift(definition.bit_mask)}"
    kind = definition.conversion_type
    if kind in (None, "IDENTICAL", "NO_COMPU_METHOD"):
        return f"phys = {raw}"
    if kind == "TAB_VERB":
        return f"{len(definition.enum_entries)} pairs"
    if kind == "LINEAR" and definition.coeffs_linear:
        a, b = definition.coeffs_linear
        if a is None or b is None:
            return ""
        scale = "" if a == 1 else f"{_coef(a)}*"
        tail = "" if b == 0 else f" + {_coef(b)}"
        return f"phys = {scale}{raw}{tail}"
    return ""


def _definition_line(row: SheetRow) -> Text:
    d = row.definition
    if d.refusal is not None:
        return _definition_text(plain(d.refusal.message))
    address = "--------" if d.address is None else f"{d.address:08X}"
    tail = [f"0x{address}", f"{d.byte_length} B"]
    if d.kind == "text":
        head = ["text"]
    else:
        formula = _formula(d)
        conversion = d.conversion_type or "NO_COMPU_METHOD"
        label = _DATATYPE_FORMATS.get(d.datatype or "", "?")
        head = [f"{conversion} {formula}".strip(), f"{d.datatype or '?'} {label} {d.byte_order}-endian"]
        if d.record_layout:
            head.append(plain(d.record_layout))
    return _definition_text(plain(" · ".join(head + tail)))


def _definition_text(body: str) -> Text:
    line = Text("└", style=_RULE)
    line.append(" " + body, style=_DIM)
    return line


def _detail_definition(row, preview, width, state, room) -> list[Text]:
    return [_definition_line(row)]


def _chosen_stored(row: SheetRow, preview: Optional[Preview]):
    if preview is not None and isinstance(preview.decoded, Decoded):
        return preview.decoded.stored
    source = row.staged if isinstance(row.staged, Decoded) else row.current
    return source.stored if isinstance(source, Decoded) else None


def _entry_matches(entry, stored) -> bool:
    if stored is None:
        return False
    if entry.raw_max is None:
        return entry.raw == stored
    return entry.raw <= stored <= entry.raw_max


def _enum_options(row: SheetRow, preview: Optional[Preview]) -> Text:
    d = row.definition
    stored = _chosen_stored(row, preview)
    chosen = next((i for i, e in enumerate(d.enum_entries) if _entry_matches(e, stored)), None)
    line = Text()
    for index, entry in enumerate(d.enum_entries):
        if index:
            line.append("   ")
        raw = _general(entry.raw)
        if entry.raw_max is not None:
            raw += f"..{_general(entry.raw_max)}"
        mark = "(●)" if index == chosen else "( )"
        line.append(f"{mark} {raw} {plain(entry.text)}", style="bold" if index == chosen else "")
    if d.default_text is not None:
        line.append(f'   default "{plain(d.default_text)}"')
    return line


def _plain_row(row: Text) -> Text:
    """A card row as CTX-PE-DEF plain text: controls replaced (same length), the text style under it."""
    row = row.copy()
    row.plain = plain(row.plain)
    row.stylize_before(_TEXT)
    return row


def _cut_cells(cell: Text, width: int) -> Text:
    """``cell`` fitted in ``width`` cells: the cut of ``clip`` (one ``…``) with the spans kept, then padded."""
    if width <= 0:
        return Text()
    cell = cell.copy()
    if cell.cell_len > width:
        keep = max(0, len(clip(cell.plain, width)) - 1)
        cell.right_crop(len(cell.plain) - keep)
        cell.append(_ELLIPSIS)
    cell.pad_right(width - cell.cell_len)
    return cell


def card_lines(title: str, rows: list[Text], cap: int) -> list[Text]:
    """The frame of a card: ``╭─ <title> ─…─╮``, ``│ <row> │`` per row, ``╰─…─╯``.

    Widths are in terminal cells; the inner width is the widest row + 2 (at least the title + 4),
    at most ``cap - 2``; the title and each row are plain text, cut with one ``…`` when too wide.
    """
    title = plain(title)
    cleaned = [_plain_row(row) for row in rows]
    inner = min(cap - 2, max([r.cell_len for r in cleaned] + [cell_len(title) + 4]) + 2)
    shown = clip(title, inner - 4)
    top = Text("╭─ ", style=_RULE)
    top.append(shown, style=_TEXT)
    top.append(" " + "─" * max(0, inner - cell_len(shown) - 3) + "╮", style=_RULE)
    lines = [top]
    for row in cleaned:
        line = Text("│ ", style=_RULE)
        line.append_text(_cut_cells(row, inner - 2))
        line.append(" │", style=_RULE)
        lines.append(line)
    lines.append(Text("╰" + "─" * inner + "╯", style=_RULE))
    for line in lines:
        line.stylize_before(f"on {_CARD_GROUND}")
    return lines


def _detail_enum(row, preview, width, state, room) -> list[Text]:
    rows = [_enum_options(row, preview), Text("↔ choose · enter stage")]
    card = card_lines(f"{row.name} · choose one", rows, max(GRID_WIDTH - 4, width))
    return [_definition_line(row)] + card


def _word(data: Sequence[Optional[int]], order: str) -> Optional[int]:
    return None if None in data else int.from_bytes(bytes(data), order)


def _bit(line: Text, text: str, style: str) -> None:
    line.append(" " * (3 - len(text)))
    line.append(text, style=style)


def bit_table(row: SheetRow, preview: Optional[Preview]) -> list[Text]:
    """The card rows of a bit mask: 4 lines (bit, before, mask, after) per 16 bits, high bits first.

    A nibble guide follows every bit whose number is a multiple of 4; the hex column is on the first
    block only; an after bit that differs from the image is underlined in the pending style; a bit
    the image does not hold is ``?``.
    """
    d = row.definition
    count = d.byte_length or 0
    before = _read(row.image, d.address, count)
    after = _after_bytes(row, preview, count)
    old, new = _word(before, d.byte_order), _word(after, d.byte_order)
    lines: list[Text] = []
    for high in range(8 * count - 1, -1, -16):
        head, bef, msk, aft = (Text(label, style=_DIM) for label in ("bit    ", "before ", "mask   ", "after  "))
        for bit in range(high, max(-1, high - 16), -1):
            masked = (d.bit_mask >> bit) & 1
            ink = _TEXT if masked else _DIM
            was = None if old is None else (old >> bit) & 1
            now = None if new is None else (new >> bit) & 1
            _bit(head, str(bit), _DIM)
            _bit(bef, "?" if was is None else str(was), ink)
            _bit(msk, "■" if masked else "·", f"bold {_RULE}" if masked else _DIM)
            _bit(aft, "?" if now is None else str(now), _CHANGED_STYLE if None not in (was, now) and was != now else ink)
            if bit % 4 == 0:
                for line in (head, bef, msk, aft):
                    line.append(" │", style=_RULE)
        if not lines:
            head.append(" hex", style=_DIM)
            bef.append(" " + _hex(before), style=_DIM)
            msk.append(f" {d.bit_mask:0{2 * count}X}", style=_DIM)
            aft.append(" " + _hex(after), style=_TEXT)
        lines += [head, bef, msk, aft]
    return lines


def _detail_mask(row, preview, width, state, room) -> list[Text]:
    card = card_lines(f"{row.name} · bit editor · other bits kept", bit_table(row, preview), max(GRID_WIDTH - 4, width))
    return [_definition_line(row)] + card


def _hex_head() -> Text:
    head = Text("off", style=_DIM)
    head.append(" │", style=_RULE)
    for column in range(16):
        head.append(f" +{column:X}", style=_DIM)
        if column == 7:
            head.append(" │", style=_RULE)
    head.append(" │", style=_RULE)
    head.append(" ASCII", style=_DIM)
    return head


def _byte_style(byte: Optional[int], changed: bool) -> str:
    if changed:
        return _CHANGED_STYLE
    return _DIM if not byte else _TEXT


def hex_grid(row: SheetRow, preview: Optional[Preview]) -> list[Text]:
    """The card rows of a text row: a head, then 16 bytes per row of the span's first 64.

    Each row is ``+<offset> │`` and the bytes after the preview (``│`` after the 8th, three spaces
    per missing byte of a short row), then ``│`` and one ASCII character per byte at a fixed
    column; a byte that differs from the image is underlined in the pending style.
    """
    d = row.definition
    span = d.byte_length or 0
    shown = min(span, _TEXT_ROWS_BYTES)
    old = _read(row.image, d.address, shown)
    new = _after_bytes(row, preview, shown)
    lines = [_hex_head()]
    for offset in range(0, shown, 16):
        line = Text(f"+{offset:02X}", style=_DIM)
        line.append(" │", style=_RULE)
        for column in range(16):
            index = offset + column
            if index < shown:
                line.append(" ")
                line.append(_hex((new[index],)), style=_byte_style(new[index], new[index] != old[index]))
            else:
                line.append("   ")
            if column == 7:
                line.append(" │", style=_RULE)
        line.append(" │", style=_RULE)
        line.append(" ")
        for index in range(offset, min(offset + 16, shown)):
            byte = new[index]
            printable = byte is not None and 0x20 <= byte <= 0x7E
            style = _CHANGED_STYLE if new[index] != old[index] else _TEXT if printable else _DIM
            line.append(chr(byte) if printable else "·", style=style)
        lines.append(line)
    if span > _TEXT_ROWS_BYTES:
        lines.append(Text(f"{_ELLIPSIS} {span - _TEXT_ROWS_BYTES} more B", style=_DIM))
    return lines


def _detail_text(row, preview, width, state, room) -> list[Text]:
    card = card_lines(f"{row.name} · text editor · 16 B per row", hex_grid(row, preview), max(GRID_WIDTH - 4, width))
    return [_definition_line(row)] + card


# --------------------------------------------------------------------------- I-8.5


class KindOps(NamedTuple):
    label: str
    editable: Callable
    decode: Callable
    value_text: Callable
    staged: Callable
    preview: Callable
    detail: Callable
    submit: Callable
    cells: Optional[Callable] = None
    bar: Optional[Callable] = None
    mark: Optional[Callable] = None  # (row, state) -> the staged/pending glyph, or None for Inc 8's rule


def _always(definition: Definition) -> bool:
    return True


def _never(definition: Definition) -> bool:
    return False


_FALLBACK_OPS = KindOps(
    "", _never, _decode_none, _value_fallback, _staged_by_bytes,
    _no_preview, _detail_definition, _no_submit,
)


def _scalar_ops(label: str, value: Callable, detail: Callable) -> KindOps:
    return KindOps(label, _always, _decode_scalar, value, _staged_by_text, preview, detail, _submit_stage)


_KIND_OPS: dict[str, KindOps] = {
    "number": _scalar_ops("new =", _value_number, _detail_definition),
    "bit mask": _scalar_ops("field =", _value_mask, _detail_mask),
    "enum": _scalar_ops("new =", _value_enum, _detail_enum),
    "text": KindOps(
        "text =", _text_editable, _decode_text, _value_text, _staged_text,
        preview, _detail_text, _submit_stage,
    ),
}


def ops_for(kind: str) -> KindOps:
    """The operations of a row kind; every other kind takes the fallback."""
    return _KIND_OPS.get(kind, _FALLBACK_OPS)


def value_text(row: SheetRow, decoded: object) -> str:
    return ops_for(row.kind).value_text(row, decoded)


def build_row(
    definition: Definition,
    a2l_data: Optional[dict],
    image: Optional[Mapping[int, int]],
    overlay: StagedOverlay,
) -> SheetRow:
    """The row of a definition: current over the image, staged over the overlay."""
    kind = row_kind(definition)
    ops = ops_for(kind)
    row = SheetRow(
        definition.name, definition, kind,
        ops.decode(definition, a2l_data, image),
        ops.decode(definition, a2l_data, overlay),
        False, image, overlay,
    )
    return replace(row, is_staged=ops.staged(row, image, overlay))


# --------------------------------------------------------------------------- delta, limits


def _resolve(value: object) -> object:
    if isinstance(value, Preview):
        return value.result if isinstance(value.result, Refusal) else value.decoded
    return value


def _changed_positions(old: str, new: str, span: int) -> int:
    old, new = old.ljust(span, "\0"), new.ljust(span, "\0")
    return sum(1 for a, b in zip(old, new) if a != b)


def _delta_number(row: SheetRow, current: Decoded, new: Decoded, staged: bool) -> str:
    a, b = _numeric(current.value), _numeric(new.value)
    if a is None or b is None:
        return ""
    delta = b - a
    decimals = row.definition.decimals
    text = _signed(f"{delta:.{decimals}f}" if decimals is not None else _general(delta))
    if staged:
        return f"{text} staged"
    limits = row.definition.limits
    lower, upper = limits.lower, limits.upper
    if lower is None or upper is None or not upper > lower:
        return text
    return f"{text} ({_signed(f'{100 * delta / (upper - lower):.1f}')}%)"


def delta_text(row: SheetRow, value: object, staged: bool) -> str:
    """The Δ text; ``✗ refused`` for a refused preview; empty when nothing is new."""
    new = _resolve(value)
    if isinstance(new, Refusal):
        return "✗ refused"
    if not isinstance(new, Decoded) or not isinstance(row.current, Decoded):
        return ""
    if row.kind == "number":
        return _delta_number(row, row.current, new, staged)
    if row.kind == "enum":
        return f"{_stored_text(row.current)} → {_stored_text(new)}"
    if row.kind == "bit mask":
        a, b = _numeric(row.current.stored), _numeric(new.stored)
        return "" if a is None or b is None else _signed(str(int(b) - int(a)))
    if row.kind == "text":
        n = _changed_positions(row.current.text, new.text, row.definition.byte_length or 0)
        return f"{n} chars"
    return ""


def _as_float(x: float) -> float:
    """A limit as a float: an integer beyond the float range is +-inf, a limit that is not finite (R-PE-DEF.117)."""
    try:
        return float(x)
    except OverflowError:
        return float("inf") if x > 0 else float("-inf")


def _bounds(row: SheetRow) -> Optional[tuple[float, float]]:
    d = row.definition
    if row.kind in ("number", "bit mask"):
        lower, upper = d.limits.lower, d.limits.upper
        return None if lower is None or upper is None else (_as_float(lower), _as_float(upper))
    if row.kind == "enum" and d.enum_entries:
        values = [e.raw for e in d.enum_entries] + [e.raw_max for e in d.enum_entries if e.raw_max is not None]
        return _as_float(min(values)), _as_float(max(values))
    return None


def _ruler_value(row: SheetRow, decoded: object) -> Optional[float]:
    if isinstance(decoded, (int, float)) and not isinstance(decoded, bool):
        return float(decoded)  # a plain value (graph limits_cell examples: value 25.5, 175)
    if not isinstance(decoded, Decoded):
        return None
    return _numeric(decoded.value if row.kind == "number" else decoded.stored)


def _exponent_form(x: float) -> str:
    """One significant digit, ``<d>e<exponent>`` (4.29e12 -> 4e12, -1.7e308 -> -2e308)."""
    mantissa, exponent = f"{x:.0e}".split("e")
    return f"{mantissa}e{int(exponent)}"


def _slot_text(x: float) -> str:
    """7 cells: the number right-aligned in 6, its unit letter (k, M, G) in the 7th, else a space."""
    text = short_number(x)
    if len(text) > 6:
        text = _exponent_form(x)
    if text[-1:] in ("k", "M", "G"):
        return text[:-1].rjust(_SLOT - 1) + text[-1]
    return text.rjust(_SLOT - 1) + " "


def limit_slot(x: float) -> Text:
    """A limit in its 7-cell slot of the limits cell, dim."""
    return Text(_slot_text(x), style=_DIM)


def range_cell(lower: Optional[float], upper: Optional[float]) -> Text:
    """The range form (both limits: ``…`` at the track's middle) or the no-limits form (``-``), 34 cells."""
    both = lower is not None and upper is not None
    left = _slot_text(lower) if both else " " * _SLOT
    right = _slot_text(upper) if both else " " * _SLOT
    middle = " " * _MIDDLE + ("…" if both else "-") + " " * (_TRACK - _MIDDLE - 1)
    return Text(f"{left} {middle} {right}", style=_DIM)


def _track_index(value: float, lower: float, upper: float, track: int) -> tuple[int, bool]:
    """(cell, beyond-an-end)."""
    if value < lower:
        return 0, True
    if value > upper:
        return track - 1, True
    pos = _position(value, lower, upper)
    return min(track - 2, max(1, 1 + int(round(pos * (track - 3))))), False


def _position(value: float, lower: float, upper: float) -> float:
    """(value - lower) / (upper - lower); on halves only when that span overflows, so a finite span always has a
    finite position (R-PE-DEF.117: the halves of a subnormal span can both be 0)."""
    span = upper - lower
    if isfinite(span):
        return (value - lower) / span
    return (value / 2 - lower / 2) / (upper / 2 - lower / 2)


def _has_position(value: float, lower: float, upper: float) -> bool:
    """A value in range has a position on the track; a value beyond an end needs none."""
    if not isfinite(value):
        return False
    if value < lower or value > upper:
        return True
    return isfinite(_position(value, lower, upper))


def _no_position_cell(lower: float, upper: float) -> Text:
    """Both slots and the bare track with ``?`` at its middle (R-PE-DEF.114)."""
    track = "├" + "─" * (_MIDDLE - 1) + "?" + "─" * (_TRACK - _MIDDLE - 2) + "┤"
    return Text(f"{_slot_text(lower)} {track} {_slot_text(upper)}", style=_DIM)


def _track_cell(lower: float, upper: float, marks: list) -> Text:
    cells = ["├"] + ["─"] * (_TRACK - 2) + ["┤"]
    styles: dict[int, str] = {}
    taken = None
    for number, glyph, style in marks:
        index, beyond = _track_index(number, lower, upper, _TRACK)
        if index == taken and not beyond:
            index = index + 1 if index + 1 <= _TRACK - 2 else index - 1
        cells[index] = "◀" if beyond and index == 0 else "▶" if beyond else glyph
        styles[index] = style
        taken = index
    line = limit_slot(lower)
    line.append(" ", style=_DIM)
    for index, char in enumerate(cells):
        line.append(char, style=styles.get(index) or _DIM)
    line.append(" ", style=_DIM)
    line.append_text(limit_slot(upper))
    return line


def limits_cell(row: SheetRow, value: object, width: int, tone: str = "") -> Text:
    """``<lower slot> <track> <upper slot>`` (34 cells) with ● at the current and ◆ at the new value.

    ``width`` is not used (the Limits width is fixed); kept so the call shape holds. ``tone`` is the
    style of the ◆ (and of a ◀ ▶ it becomes). A limit that is not finite, or an upper not above the
    lower, gives the range form; a value or a position that is not finite gives the no-position form.
    """
    bounds = _bounds(row)
    if bounds is None:
        return range_cell(None, None)
    lower, upper = bounds
    if not (isfinite(lower) and isfinite(upper) and upper > lower):
        return range_cell(lower, upper)
    marks = []
    for decoded, glyph, style in ((row.current, "●", f"bold {_TEXT}"), (_resolve(value), "◆", tone)):
        number = _ruler_value(row, decoded)
        if number is not None:
            marks.append((number, glyph, style))
    if not all(_has_position(number, lower, upper) for number, _glyph, _style in marks):
        return _no_position_cell(lower, upper)
    return _track_cell(lower, upper, marks)


# --------------------------------------------------------------------------- row line


def _base_text(row: SheetRow) -> str:
    return row.current.text if row.kind == "text" and isinstance(row.current, Decoded) else ""


def _is_pending(row: SheetRow, pending: Optional[str]) -> bool:
    """Pending while a formula text exists and differs from the base text (an empty text on a
    text row is an edit: it stages NULs)."""
    return pending is not None and pending != _base_text(row)


def _new_value(row: SheetRow, pending: bool, preview: Optional[Preview]) -> object:
    if pending and preview is not None:
        return _resolve(preview)
    return row.staged if row.is_staged and not pending else None


def _new_cell_text(row: SheetRow, pending: Optional[str], is_pending: bool, new: object) -> str:
    if isinstance(new, Decoded):
        return value_text(row, new)
    return pending if is_pending else "·"


def _delta_cell(row: SheetRow, is_pending: bool, preview: Optional[Preview]) -> str:
    if is_pending:
        return delta_text(row, preview, False) if preview is not None else ""
    return delta_text(row, row.staged, True) if row.is_staged else ""


_GLYPH_STYLES = {"●": _STAGED_STYLE, "◆": _PENDING_STYLE}


def _tone(row: SheetRow, is_pending: bool, preview: object, glyph: Optional[str] = None) -> str:
    """The style of the row's New and Δ cells: a ``KindOps.mark`` glyph decides for a bench row."""
    if glyph is not None:
        return _GLYPH_STYLES.get(glyph[:1], "")
    if is_pending:
        refused = isinstance(preview, Preview) and isinstance(preview.result, Refusal)
        return _REFUSED_STYLE if refused else _PENDING_STYLE
    return _STAGED_STYLE if row.is_staged else ""


def _mark(selected: bool, staged: bool, pending: bool, glyph: Optional[str] = None) -> Text:
    mark = Text("▶" if selected else " ", style=f"bold {_RULE}" if selected else "")
    if glyph is None:
        glyph = "●" if staged else "◆" if pending else " "
    glyph = glyph[:1] or " "
    mark.append(glyph, style=_GLYPH_STYLES.get(glyph, ""))
    return mark


def _stock_cells(row, widths, is_pending, pending, preview, new, tone) -> tuple:
    ops = ops_for(row.kind)
    shown = new if isinstance(new, Decoded) else None
    return (
        _text_cell(kind_word(row.definition), widths.kind, _DIM),
        _text_cell(ops.value_text(row, row.current), widths.current, _TEXT),
        _text_cell(_new_cell_text(row, pending, is_pending, new), widths.new),
        _fit(limits_cell(row, shown, widths.limits, tone), widths.limits),
        _text_cell(_delta_cell(row, is_pending, preview), widths.delta),
    )


def _bench_cells(row, state, widths) -> tuple:
    """The kind's own cells fitted to the grid; Kind dim, Current in the text style under its spans."""
    cells = [
        _fit(c.copy(), w) for c, w in zip(
            ops_for(row.kind).cells(row, state, widths),
            (widths.kind, widths.current, widths.new, widths.limits, widths.delta))
    ]
    cells[0].stylize_before(_DIM)
    cells[1].stylize_before(_TEXT)
    return tuple(cells)


def row_line(
    row: SheetRow,
    widths: SheetWidths,
    selected: bool,
    pending: Optional[str],
    preview: Optional[Preview],
    state: object = None,
    odd: bool = False,
) -> Text:
    """One sheet row of the grid: mark, then each cell at its width and its gutter ``│``.

    ``pending`` is the row's formula text, None when it has none; ``odd`` is the zebra ground of
    an odd page position (the selected ground wins)."""
    ops = ops_for(row.kind)
    is_pending = _is_pending(row, pending)
    new = _new_value(row, is_pending, preview)
    glyph = ops.mark(row, state) if ops.mark is not None else None
    tone = _tone(row, is_pending, preview, glyph)
    if ops.cells is not None:
        cells = _bench_cells(row, state, widths)
    else:
        cells = _stock_cells(row, widths, is_pending, pending, preview, new, tone)
    kind_c, current_c, new_c, limits_c, delta_c = cells
    new_c.stylize(tone or _DIM)
    delta_c.stylize(tone or _DIM)
    name_c = _text_cell(row.name, widths.name, f"bold {_TEXT}" if selected else _TEXT)
    unit_c = _text_cell(row.definition.unit or "", widths.unit, _DIM)
    line = _mark(selected, row.is_staged, is_pending, glyph)
    for cell in (name_c, kind_c, current_c, new_c, unit_c, limits_c, delta_c):
        line.append_text(cell)
        line.append("│", style=_RULE)
    ground = _SELECTED_GROUND if selected else _ODD_GROUND if odd else None
    if ground is not None:
        line.stylize_before(f"on {ground}")
    return line


# --------------------------------------------------------------------------- detail, window, bar


def detail_lines(
    row: SheetRow,
    preview: Optional[Preview],
    width: int,
    state: object = None,
    room: Optional[int] = None,
) -> list[Text]:
    """The selected row's expanded object: its detail lines after the bar ``  ┊ ``, on the expanded ground.

    ``width`` is the view width V: the kind lays its detail out for V - 4 cells; every line is cut
    at max(GRID_WIDTH, V) - 4 cells with one ``…`` and padded with the ground to max(GRID_WIDTH, V).
    ``room`` (the body lines left for the detail) is the kind's to size by; the cut to ``room``
    lines is ``row_window``'s."""
    lines = ops_for(row.kind).detail(row, preview, width - 4, state, room if room is not None else 10**9)
    cap = max(GRID_WIDTH, width)
    shown = []
    for content in lines:
        line = Text("  ┊ ", style=_RULE)
        line.append_text(_trim(content, cap - 4))
        line.pad_right(cap - line.cell_len)
        line.stylize_before(f"on {_EXPANDED_GROUND}")
        shown.append(line)
    return shown


def row_window(selected: int, top: int, visible: int, detail: int) -> tuple[int, int]:
    """(top, detail lines painted): the selected row and its cut detail always lie in the body."""
    visible = max(1, visible)
    painted = max(0, min(detail, visible - 1))
    need = 1 + painted
    if selected < top:
        top = selected
    elif selected + need > top + visible:
        top = selected + need - visible
    return max(0, top), painted


def formula_fill(row: SheetRow, pending: Optional[str]) -> str:
    """The text the formula input takes for the row: pending, else the base text; ≤ 4,096."""
    if not ops_for(row.kind).editable(row.definition):
        return ""
    text = pending if pending is not None else _base_text(row)
    return text[:_FILL_MAX]


def _cut(line: Text, width: int) -> Text:
    return _trim(line, width)


def _verdict(preview: Preview) -> Text:
    notices = preview.result.notices
    if notices:
        return Text("▲ " + plain(notices[0]), style=_NOTICE)
    return Text("✓ in limits", style=_STAGED)


def _scalar_head(row: SheetRow, width: int) -> list[str]:
    parts = []
    if row.definition.unit:
        parts.append(plain(row.definition.unit))
    bounds = _bounds(row)
    if width >= 110 and bounds is not None:
        parts.append(f"({short_number(bounds[0])} {_ELLIPSIS} {short_number(bounds[1])})")
    return parts


def _scalar_tail(row: SheetRow, preview: Preview, width: int) -> Text:
    d = row.definition
    span = d.byte_length or 0
    before = _hex_first8(_read(row.image, d.address, min(span, 8)), span)
    after = _hex_first8(_after_bytes(row, preview, min(span, 8)), span)
    tail = Text()
    for part in _scalar_head(row, width):
        tail.append(part + "  ", style=_DIM)
    tail.append(f"raw {_stored_text(row.current)}→{_stored_text(preview.decoded)} · {before} → ", style=_DIM)
    tail.append(after, style=_PENDING_STYLE)
    tail.append("  ")
    tail.append_text(_verdict(preview))
    tail.append("  ")
    tail.append("enter stage ↓", style=f"bold {_KEY_INK} on {_RULE}")
    return tail


def formula_tail(row: SheetRow, preview: Optional[Preview], width: int) -> Text:
    """The tail of the formula bar, cut at ``width`` with one ``…``."""
    if not ops_for(row.kind).editable(row.definition):
        return _cut(Text(f"edit {plain(kind_word(row.definition))} objects in the Inspector tab"), width)
    if preview is None:
        return _cut(Text("  ".join(_scalar_head(row, width)) if row.kind != "text" else ""), width)
    if isinstance(preview.result, Refusal):
        return _cut(Text("✗ " + plain(preview.result.message), style=_REFUSED), width)
    if row.kind == "text":
        count = len(preview.decoded.text) if isinstance(preview.decoded, Decoded) else 0
        text = f"{count}/{row.definition.byte_length} chars · NUL-padded  enter stage ↓"
        return _cut(Text(text), width)
    return _cut(_scalar_tail(row, preview, width), width)
