"""Batch-103 Inc 12 (G-T1) — the A2L tag table paints no glued or cut values.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-12/01-requirements.md``
rows R-TUI-042a.2 … .8 and the acceptance case AT-B103-I12-1 — one test per
case of ``inc-12/02-test-cases.md`` (AT-B103-I12-2 stays the operator's
real-terminal gate). The implementer's branch is not read here: every oracle
comes from the approved requirements, cases and graph.

Fixtures SYNMAP, LONGMAP(n), PAGE64(n), PAGE64W(n) and MANY(k, n) are built
synthetically in-file (no operator or public-corpus text). The real app is
driven headless through ``run_test`` / ``projects.run_app`` with real
loading, paging, resize and Save-project write routes; painted cell text and
painted geometry are read back from ``#a2l_tags_list`` and ``#a2l_detail_card``.

Traceability (E4): test names start ``test_r_tui_042a_<row>_<case>_`` (or
``test_at_b103_i12_1_`` for the acceptance case) so ``trace_check`` and the
case table bind them.

Independence: the expected shortened names are computed here from the formula
of R-TUI-042a.3/.5/.6 (never the product's ``_shorten_tag_name``), and *w* is
computed from the measured table geometry (``scrollable_content_region``,
``Column.get_render_width``, ``cell_padding``, ``fixed_columns``), never from
the case's terminal width.
"""
from __future__ import annotations

import inspect
import json
import re
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import pytest
from rich.cells import cell_len
from rich.text import Text
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input

from s19_app.tui.app import A2LDetailCard, S19TuiApp
from s19_app.tui.changes.io import emit_s19_from_mem_map
from s19_app.tui.screens_directionb import PatchEditorPanel

from tests.support import b100_projects as projects
from tests.support import b100_save_dialog as sd
from tests.support.b100_workers import settle_workers
from tests.support.timing import report_margin, wait_until


# ---------------------------------------------------------------------------
# Synthetic fixture builders (SYNMAP, LONGMAP(n), PAGE64(n), PAGE64W(n), MANY)
# ---------------------------------------------------------------------------

ADDR = 0x1C2D3E00
ADDR64 = 0x1C2D3E004026
ADDR16 = 0xFEDCBA9876543210
NX, NY = 87, 13
MAP_LEN = 2 + 2 + NX * NY * 2  # 2266

ADDR_STR = f"0x{ADDR:08X}"
ADDR64_STR = f"0x{ADDR64:08X}"
ADDR_0x1000_STR = "0x00001000"
ADDR16_STR = f"0x{ADDR16:08X}"

HEAD = """ASAP2_VERSION 1 71
/begin PROJECT PSYN ""
/begin MODULE MSYN ""
/begin MOD_COMMON ""
BYTE_ORDER MSB_LAST
/end MOD_COMMON
/begin COMPU_METHOD CM_SYN "" IDENTICAL "%.0" ""
/end COMPU_METHOD
/begin RECORD_LAYOUT RL_SYN_MAP
NO_AXIS_PTS_X 1 UWORD
NO_AXIS_PTS_Y 2 UWORD
FNC_VALUES 3 UWORD COLUMN_DIR DIRECT
/end RECORD_LAYOUT
"""
TAIL = "/end MODULE\n/end PROJECT\n"


def longname(n: int) -> str:
    """LONGMAP(n): ``SYN_MAP_`` + ``L`` × (n − 12) + ``_END``."""
    return "SYN_MAP_" + "L" * (n - 12) + "_END"


def name_of(prefix: str, n: int) -> str:
    """PAGE64(n) / MANY names: ``(prefix + ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 × 4)[:n]``."""
    return (prefix + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" * 4)[:n]


def map_block(name: str, display_identifier: Optional[str] = None) -> str:
    disp = f"  DISPLAY_IDENTIFIER {display_identifier}\n" if display_identifier else ""
    return f"""/begin CHARACTERISTIC {name} "synthetic map"
  MAP 0x{ADDR:08X} RL_SYN_MAP 4095 CM_SYN 0 4095
  /begin AXIS_DESCR
    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {NX} 0 {NX - 1}
    FIX_AXIS_PAR 0 1 {NX}
  /end AXIS_DESCR
  /begin AXIS_DESCR
    FIX_AXIS NO_INPUT_QUANTITY CM_SYN {NY} 0 {NY - 1}
    FIX_AXIS_PAR 0 1 {NY}
  /end AXIS_DESCR
{disp}/end CHARACTERISTIC
"""


def meas(name: str, addr: int, dtype: Optional[str] = "UWORD", length: Optional[int] = None) -> str:
    hexdig = max(8, len(f"{addr:X}"))
    dt = f"  {dtype} CM_SYN 0 0 0 65535\n" if dtype is not None else ""
    extra = f"  LENGTH {length}\n" if length is not None else ""
    return (f'/begin MEASUREMENT {name} "synthetic"\n{dt}'
            f"  ECU_ADDRESS 0x{addr:0{hexdig}X}\n{extra}/end MEASUREMENT\n")


def page_syn() -> str:
    """SYNMAP — the synthetic MAP named ``SYN_MAP_W`` (9 characters)."""
    return HEAD + map_block("SYN_MAP_W") + TAIL


def page_long(n: int) -> str:
    """LONGMAP(n) — SYNMAP with its name replaced by ``longname(n)``."""
    return HEAD + map_block(longname(n)) + TAIL


def page64(n: int, wide16: bool = False) -> str:
    """PAGE64(n) — F's page: the MAP, a 64-bit MEASUREMENT, a 1 MiB-length
    MEASUREMENT; PAGE64W adds the 16-digit-address MEASUREMENT."""
    body = (map_block(name_of("SYN_MAP_", n)) + meas(name_of("SYN_V64_", n), ADDR64)
            + meas(name_of("SYN_BIG_", n), 0x1000, None, 1048576))
    if wide16:
        body += meas(name_of("SYN_W16_", n), ADDR16)
    return HEAD + body + TAIL


def page_many(count: int, n: int, wide_at: Optional[int] = None) -> str:
    """MANY(k, n) — LONGMAP(n)'s MAP plus ``count`` MEASUREMENTs at 0x2000 + 2i
    (MEASUREMENT ``wide_at`` at the 64-bit address instead)."""
    body = map_block(longname(n))
    for i in range(count):
        addr = ADDR64 if i == wide_at else 0x2000 + 2 * i
        body += meas(name_of(f"SYN_M{i:03d}_", n), addr)
    return HEAD + body + TAIL


# ---------------------------------------------------------------------------
# Independent oracles (never the product's helpers)
# ---------------------------------------------------------------------------

#: The whole control class R-TUI-042a.7.1 removes: C0 (0x00-0x1F), DEL (0x7F)
#: and C1 (0x80-0x9F).
_CONTROL = frozenset(range(0x00, 0x20)) | frozenset(range(0x7F, 0xA0))

#: The four synthetic control sequences R-TUI-042a.7.1 holds, each with its
#: introducer and a distinctive payload (so the screen-output check cannot
#: collide with the terminal's own SGR colour escapes).
_SEQ_ESC = "\x1b]0;PWN"   # ESC + OSC title "PWN"
_SEQ_CSI = "\x9b31m"        # single-byte CSI
_SEQ_OSC = "\x9d0;x"        # single-byte OSC
_SEQ_DCS = "\x90q\x7f"      # DCS, payload "q" + one DEL (U+007F)
#: The same four sequences with their introducer, for the screen-output check.
_INTRODUCER_SEQS = ("\x1b]0;PWN", "\x9b31m", "\x9d0;x", "\x90q")


def _project(name: str) -> str:
    """R-TUI-042a.6's projection: each character outside U+0021 … U+007E as U+FFFD."""
    return "".join(ch if 0x21 <= ord(ch) <= 0x7E else "\ufffd" for ch in name)


def _shorten(name: str, width: int) -> str:
    """The middle cut of R-TUI-042a.3/.5, written out independently."""
    if width < 1:
        width = 1
    if len(name) <= width:
        return _project(name)
    head = (width - 1) // 2
    tail = width - 1 - head
    return _project(name[:head]) + "…" + _project(name[len(name) - tail:])


def expected_tag(name: str, w: Optional[int]) -> str:
    """The Tag cell's name portion: the 34-cell form when ``w`` is None or ≥ 34,
    else the *w*-cell form (``min(34, w)``)."""
    width = 34 if (w is None or w >= 34) else w
    return _shorten(name, width)


def _hostile(prefix: str, suffix: str) -> tuple[str, str]:
    """A value holding the four sequences and its projected (control-free) form."""
    value = prefix + _SEQ_ESC + _SEQ_CSI + _SEQ_OSC + _SEQ_DCS + suffix
    scrubbed = prefix + "]0;PWN31m0;xq" + suffix
    return value, scrubbed


# ---------------------------------------------------------------------------
# Drive helpers (the real app, headless)
# ---------------------------------------------------------------------------


def _write_image(base: Path) -> Path:
    img = base / "syn_img.s19"
    img.write_text(
        emit_s19_from_mem_map(
            {ADDR + i: (i * 7) & 0xFF for i in range(MAP_LEN)}, [(ADDR, ADDR + MAP_LEN)]
        ),
        encoding="ascii",
    )
    return img


def _write_a2l(base: Path, text: str, name: str = "syn.a2l") -> Path:
    a2l = base / name
    a2l.write_text(text, encoding="utf-8")
    return a2l


async def _settle(pilot, rounds: int = 8) -> None:
    for _ in range(rounds):
        await pilot.pause()


def _tag_table(app) -> DataTable:
    return app.query_one("#a2l_tags_list", DataTable)


def _card(app) -> A2LDetailCard:
    return app.query_one("#a2l_detail_card", A2LDetailCard)


async def _load(app, pilot, base: Path, a2l_path: Path) -> None:
    img = base / "syn_img.s19"
    await pilot.pause()
    app.load_selected_file(img)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == img.name,
        f"the image load of {img.name}",
    )
    app.load_a2l_from_path(a2l_path)
    await settle_workers(pilot)
    await _settle(pilot)


async def _show_a2l(app, pilot) -> DataTable:
    app.set_focus(None)
    await pilot.press("2")
    await wait_until(
        pilot,
        lambda: app._active_screen_key == "a2l" and _tag_table(app).region.height > 0,
        "the A2L Explorer did not show",
    )
    table = _tag_table(app)
    table.focus()
    if table.row_count:
        table.move_cursor(row=0)
    await _settle(pilot, 10)
    return table


def _explore(tmp_path: Path, a2l_text: str, size: tuple[int, int], scenario, *, scrolled: bool = False) -> None:
    """Boot the app, load the synthetic image + A2L, show the Explorer, then
    run ``scenario(app, pilot, table)``."""
    base = tmp_path / "app"
    base.mkdir(parents=True, exist_ok=True)
    _write_image(base)
    a2l = _write_a2l(base, a2l_text)

    async def _run(app, pilot, log):
        await _load(app, pilot, base, a2l)
        table = await _show_a2l(app, pilot)
        if scrolled:
            table.scroll_to(x=table.max_scroll_x, animate=False)
            await _settle(pilot, 10)
        result = scenario(app, pilot, table)
        if inspect.isawaitable(result):
            await result

    projects.run_app(base, _run, size=size)


# ---------------------------------------------------------------------------
# Geometry (computed from the actual table, never from the terminal width)
# ---------------------------------------------------------------------------


def _geom(table) -> SimpleNamespace:
    cols = [(str(c.label), c.get_render_width(table)) for c in table.ordered_columns]
    idx = {lab: i for i, (lab, _) in enumerate(cols)}
    xs: list[int] = []
    x = 0
    for _lab, cw in cols:
        xs.append(x)
        x += cw
    fixed = table.fixed_columns
    fixed_w = sum(cw for _lab, cw in cols[:fixed])
    visible = table.scrollable_content_region.width
    w = None
    if visible > 0:
        # width left = visible − Address − Length (each render width holds its
        # 2 padding cells); name width = width left − 4 (Tag padding, glyph, blank)
        w = visible - cols[0][1] - cols[1][1] - (2 * table.cell_padding + 2)
    return SimpleNamespace(
        cols=cols, idx=idx, xs=xs, fixed=fixed, fixed_w=fixed_w,
        visible=visible, sx=int(table.scroll_x), sy=int(table.scroll_y),
        padding=table.cell_padding, w=w,
    )


def _tag_index(table) -> int:
    for i, col in enumerate(table.ordered_columns):
        if str(col.label) == "Tag":
            return i
    raise AssertionError(f"no Tag column in {[str(c.label) for c in table.ordered_columns]}")


def _painted_lines(widget) -> list[str]:
    return [widget.render_line(y).text.rstrip("\n") for y in range(widget.size.height)]


def _cell_whole_in_painted(table, geom, row_index: int, col_index: int) -> bool:
    """True iff the cell at (row_index, col_index) paints its text whole."""
    lines = _painted_lines(table)
    y = 1 + row_index - geom.sy
    if y < 1 or y >= len(lines) - 1:
        return True  # off-screen: nothing to check
    line = lines[y]
    want = table.get_row_at(row_index)[col_index].plain
    if col_index < geom.fixed:
        a, b = geom.xs[col_index], geom.xs[col_index] + geom.cols[col_index][1]
    else:
        a = max(geom.fixed_w, geom.xs[col_index] - geom.sx)
        b = geom.xs[col_index] - geom.sx + geom.cols[col_index][1]
    if a >= geom.visible or b <= 0:
        return True
    return line[a:min(b, geom.visible)].strip() == want


def _cell_span(geom, col_index: int) -> tuple[int, int]:
    """The column's painted span ``(start, end)`` in painted-line x cells."""
    if col_index < geom.fixed:
        return geom.xs[col_index], geom.xs[col_index] + geom.cols[col_index][1]
    a = max(geom.fixed_w, geom.xs[col_index] - geom.sx)
    return a, geom.xs[col_index] - geom.sx + geom.cols[col_index][1]


def _painted_tag_cell(table, geom, row_index: int) -> Optional[tuple[str, int]]:
    """The Tag cell as actually painted on ``row_index``: ``(text, end_x)`` —
    the visible painted text (padding stripped) and the x of its last painted
    character, both read from the rendered line; ``None`` when the row is
    vertically off-screen. This is R-TUI-042a.5's painted-result oracle:
    stored cell length plus x is not a painted result."""
    lines = _painted_lines(table)
    y = 1 + row_index - geom.sy
    if y < 1 or y >= len(lines) - 1:
        return None
    line = lines[y]
    a, b = _cell_span(geom, geom.idx["Tag"])
    a = max(0, a)
    b = min(b, geom.visible)
    if a >= b:
        return "", -1
    seg = line[a:b]
    stripped = seg.strip(" ")
    if not stripped:
        return "", -1
    end = a + len(seg.rstrip(" ")) - 1
    return stripped, end


def _assert_painted_tag_cell(table, geom, row_index: int, want: str) -> None:
    """The painted Tag cell reads exactly ``want`` — glyph, ``…`` and suffix
    included — and its last painted character lies inside the visible width.
    Only a vertically off-screen row is skipped; an on-screen blank or fully
    clipped Tag cell is a failure, not a skip."""
    result = _painted_tag_cell(table, geom, row_index)
    if result is None:
        return  # vertically off-screen row: nothing paints to assert
    painted, end = result
    assert painted == want, (row_index, painted, want)
    assert end != -1 and end + 1 <= geom.visible, (row_index, end, geom.visible)


def _tags_of(app, table) -> list:
    out = []
    for r in range(table.row_count):
        key = table.coordinate_to_cell_key(Coordinate(r, 0)).row_key.value
        out.append(app._a2l_row_key_to_tag.get(key))
    return out


def _rows_match_form(app, table, geom, w: Optional[int]) -> bool:
    tag_idx = geom.idx["Tag"]
    for r, tag in enumerate(_tags_of(app, table)):
        if tag is None:
            return False
        glyph = "✓" if tag.get("in_memory") else "·"
        want = f"{glyph} {expected_tag(str(tag.get('name') or 'UNKNOWN'), w)}"
        if table.get_row_at(r)[tag_idx].plain != want:
            return False
    return True


def _all_rows_in_measured_form(app, table) -> bool:
    geom = _geom(table)
    if geom.w is None or geom.w < 0:
        return False
    return _rows_match_form(app, table, geom, geom.w)


def _assert_all_rows_form_and_inside(app, table, geom, w: Optional[int]) -> None:
    assert _rows_match_form(app, table, geom, w), "a Tag cell is not in the expected form"
    for r in range(table.row_count):
        _assert_painted_tag_cell(table, geom, r, table.get_row_at(r)[geom.idx["Tag"]].plain)


def _hex_runs(text: str) -> list[str]:
    return re.findall(r"0x[0-9A-F]+", text)


# ---------------------------------------------------------------------------
# R-TUI-042a.2 — one blank column between adjacent cells
# ---------------------------------------------------------------------------

#: The four glued/cut strings that must never paint on a SYNMAP page.
_GLUED = ("0x1C2D3E002266", "SYN_MAP_W0x1C2D3E00", "17921792", "unknown0..")


def _assert_adjacent_cell_gaps(table, geom, row_index: int) -> None:
    """Every adjacent pair of columns both painting on screen has at least one
    blank column between them (R-TUI-042a.2's gap, read from the painted line —
    not from stored geometry alone). Each cell's span is clipped to the
    viewport, so a partially visible right-hand cell (the 80-column Source
    example) is checked on its visible part, not skipped."""
    lines = _painted_lines(table)
    y = 1 + row_index - geom.sy
    if y < 1 or y >= len(lines) - 1:
        return  # off-screen: nothing paints, nothing to check
    line = lines[y]
    for i in range(len(geom.xs) - 1):
        a_i, b_i = _cell_span(geom, i)
        a_j, b_j = _cell_span(geom, i + 1)
        a_i = max(0, a_i)
        b_i = min(b_i, geom.visible)
        a_j = max(0, a_j)
        b_j = min(b_j, geom.visible)
        if a_i >= b_i or a_j >= b_j:
            continue  # one cell paints nothing here
        left = line[a_i:b_i].rstrip(" ")
        right = line[a_j:b_j].lstrip(" ")
        if not left or not right:
            continue  # an empty cell paints nothing to glue
        left_end = a_i + len(left) - 1
        right_start = a_j + (len(line[a_j:b_j]) - len(right))
        assert right_start - left_end - 1 >= 1, (i, i + 1, left, right, line)


def _assert_synmap_gap(app, table, width: int) -> None:
    geom = _geom(table)
    tag_idx = geom.idx["Tag"]
    # Every adjacent pair of cells paints with ≥ 1 blank between (the general
    # gap, not only Address/Length).
    _assert_adjacent_cell_gaps(table, geom, 0)
    # Address and Length are separate cells with ≥ 1 blank between them.
    assert _cell_whole_in_painted(table, geom, 0, 0), "Address not whole"
    assert _cell_whole_in_painted(table, geom, 0, 1), "Length not whole"
    assert table.get_row_at(0)[0].plain == ADDR_STR
    assert table.get_row_at(0)[1].plain == "2266"
    assert table.get_row_at(0)[tag_idx].plain == "✓ SYN_MAP_W"
    joined = "\n".join(_painted_lines(table)) + "\n" + "\n".join(_painted_lines(_card(app)))
    for glued in _GLUED:
        assert glued not in joined, (glued, width)


def test_r_tui_042a_2_1_gap_at_220_and_160(tmp_path: Path) -> None:
    """R-TUI-042a.2 case /1: SYNMAP at 220×50 and 160×50 — Address and Length
    in separate cells with a blank between, the glued strings painted 0 times."""
    for width in (220, 160):
        _explore(tmp_path, page_syn(), (width, 50), lambda app, pilot, table: _assert_synmap_gap(app, table, width))


def test_r_tui_042a_2_2_gap_at_118_100_80(tmp_path: Path) -> None:
    """R-TUI-042a.2 case /2: as /1 at 118×50, 100×50 and 80×50."""
    for width in (118, 100, 80):
        _explore(tmp_path, page_syn(), (width, 50), lambda app, pilot, table: _assert_synmap_gap(app, table, width))


# ---------------------------------------------------------------------------
# R-TUI-042a.3 — the 34-cell Tag cap
# ---------------------------------------------------------------------------


def _assert_capped(app, table, n: int) -> None:
    geom = _geom(table)
    tag_idx = geom.idx["Tag"]
    cell = table.get_row_at(0)[tag_idx].plain
    assert cell == "✓ " + _shorten(longname(n), 34), (cell, n)
    assert "…" in cell and cell_len(cell) == 36, (cell, n)
    # Address and Length painted whole; no prefix shorter than 10 chars painted
    # as the Address cell.
    assert _cell_whole_in_painted(table, geom, 0, 0)
    assert _cell_whole_in_painted(table, geom, 0, 1)
    lines = _painted_lines(table)
    for line in lines:
        for run in _hex_runs(line):
            assert run == ADDR_STR, (run, n)


def test_r_tui_042a_3_1_tag_cap_at_118(tmp_path: Path) -> None:
    """R-TUI-042a.3 case /1: LONGMAP(46/48/50/54) at 118×54 — 36-cell Tag cell,
    Address and Length whole, no shortened address prefix."""
    for n in (46, 48, 50, 54):
        _explore(tmp_path, page_long(n), (118, 54),
                 lambda app, pilot, table, n=n: _assert_capped(app, table, n))


def test_r_tui_042a_3_2_tag_cap_at_220(tmp_path: Path) -> None:
    """R-TUI-042a.3 case /2: LONGMAP(100) at 220×60 — the 34-cell form."""
    _explore(tmp_path, page_long(100), (220, 60),
             lambda app, pilot, table: _assert_capped(app, table, 100))


def test_r_tui_042a_3_3_cap_edge(tmp_path: Path) -> None:
    """R-TUI-042a.3 case /3: LONGMAP(34) whole with no ``…``; LONGMAP(35) cut."""
    for n, want_ellipsis in ((34, False), (35, True)):
        async def _check(app, pilot, table, n=n, want_ellipsis=want_ellipsis):
            geom = _geom(table)
            cell = table.get_row_at(0)[geom.idx["Tag"]].plain
            assert cell == "✓ " + _shorten(longname(n), 34), (cell, n)
            assert ("…" in cell) is want_ellipsis, (cell, n)

        _explore(tmp_path, page_long(n), (118, 54), _check)


def test_r_tui_042a_3_4_card_keeps_the_full_name(tmp_path: Path) -> None:
    """R-TUI-042a.3 case /4: LONGMAP(48) at 118×54 — the card's painted lines
    hold the 48-character name whole and one line holds the address whole."""
    async def _check(app, pilot, table):
        card = _card(app)
        lines = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
        joined = "".join(lines)
        assert longname(48) in joined, (longname(48), joined)
        assert any(ADDR_STR in ln for ln in lines), lines

    _explore(tmp_path, page_long(48), (118, 54), _check)


# ---------------------------------------------------------------------------
# R-TUI-042a.4 — Address and Length first, fixed, whole at every width
# ---------------------------------------------------------------------------

_EXPECTED_ADDRS = [ADDR_STR, ADDR64_STR, ADDR_0x1000_STR]
_EXPECTED_LENS = ["2266", "2", "1048576"]
_P64_WIDTHS = (80, 85, 90, 95, 100, 118, 160, 220)
_P64_NAMES = (20, 28, 34, 48, 100)


def _assert_p64_whole(app, table) -> None:
    geom = _geom(table)
    for r in range(table.row_count):
        cells = table.get_row_at(r)
        assert cells[0].plain == _EXPECTED_ADDRS[r], (r, cells[0].plain)
        assert cells[1].plain == _EXPECTED_LENS[r], (r, cells[1].plain)
        assert _cell_whole_in_painted(table, geom, r, 0), (r, "Address")
        assert _cell_whole_in_painted(table, geom, r, 1), (r, "Length")


@pytest.mark.parametrize("width", _P64_WIDTHS)
@pytest.mark.parametrize("n", _P64_NAMES)
def test_r_tui_042a_4_1_address_length_whole_unscrolled(tmp_path: Path, width: int, n: int) -> None:
    """R-TUI-042a.4 case /1: PAGE64(n) unscrolled — Address and Length whole in
    the first two columns, 40/40."""
    _explore(tmp_path, page64(n), (width, 54), lambda app, pilot, table: _assert_p64_whole(app, table))


@pytest.mark.parametrize("width", _P64_WIDTHS)
@pytest.mark.parametrize("n", _P64_NAMES)
def test_r_tui_042a_4_2_address_length_whole_scrolled(tmp_path: Path, width: int, n: int) -> None:
    """R-TUI-042a.4 case /2: PAGE64(n) scrolled fully right — Address and
    Length still whole (fixed columns), 40/40."""
    _explore(tmp_path, page64(n), (width, 54),
             lambda app, pilot, table: _assert_p64_whole(app, table), scrolled=True)


def test_r_tui_042a_4_3_widest_address_at_80(tmp_path: Path) -> None:
    """R-TUI-042a.4 case /3: PAGE64W(48) at 80×54 — the 16-digit address whole
    unscrolled and scrolled fully right, every Length whole."""
    def _check(app, pilot, table):
        geom = _geom(table)
        assert table.row_count == 4, table.row_count
        widest = table.get_row_at(3)
        assert widest[0].plain == ADDR16_STR, widest[0].plain
        for r in range(table.row_count):
            cells = table.get_row_at(r)
            assert cells[0].plain in (ADDR_STR, ADDR64_STR, ADDR_0x1000_STR, ADDR16_STR)
            assert cells[1].plain in ("2266", "2", "1048576")
            assert _cell_whole_in_painted(table, geom, r, 0), r
            assert _cell_whole_in_painted(table, geom, r, 1), r

    _explore(tmp_path, page64(48, wide16=True), (80, 54), _check)
    _explore(tmp_path, page64(48, wide16=True), (80, 54), _check, scrolled=True)


def test_r_tui_042a_4_4_column_order(tmp_path: Path) -> None:
    """R-TUI-042a.4 case /4: SYNMAP at 118×54 — the 16 labels in CTX-A2L-SCREEN
    order, the header's first label ``Address`` at x 1."""
    def _check(app, pilot, table):
        labels = [str(c.label) for c in table.ordered_columns]
        assert labels == [
            "Address", "Length", "Tag", "Source", "Raw", "Physical", "InMem",
            "Region", "Limits", "Unit", "Bits", "Endian", "Virt", "Func",
            "Access", "Dtype",
        ], labels
        header = table.render_line(0).text
        assert header.find("Address") == 1, repr(header)

    _explore(tmp_path, page_syn(), (118, 54), _check)


# ---------------------------------------------------------------------------
# R-TUI-042a.5 — the Tag cell sized from the width left
# ---------------------------------------------------------------------------


def test_r_tui_042a_5_1_width_left_on_a_32_bit_page(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /1: LONGMAP(48) at 80/95/100 (*w* = 14/22/25)."""
    expected = {
        80: (14, "✓ SYN_MA…LLL_END"),
        95: (22, "✓ SYN_MAP_LL…LLLLLLL_END"),
        100: (25, "✓ SYN_MAP_LLLL…LLLLLLLL_END"),
    }
    for width, (w, want) in expected.items():
        async def _check(app, pilot, table, w=w, want=want):
            geom = _geom(table)
            assert geom.w == w, (geom.w, w)
            cell = table.get_row_at(0)[geom.idx["Tag"]].plain
            assert cell == want, (cell, want)
            _assert_painted_tag_cell(table, geom, 0, cell)

        _explore(tmp_path, page_long(48), (width, 54), _check)


def test_r_tui_042a_5_2_short_name_cut_too_at_80(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /2: LONGMAP(20) at 80 (*w* = 14) — 6 + ``…`` + 7."""
    async def _check(app, pilot, table):
        geom = _geom(table)
        assert geom.w == 14, geom.w
        cell = table.get_row_at(0)[geom.idx["Tag"]].plain
        assert cell == "✓ " + _shorten(longname(20), 14), cell
        assert cell == "✓ SYN_MA…LLL_END", cell
        _assert_painted_tag_cell(table, geom, 0, cell)

    _explore(tmp_path, page_long(20), (80, 54), _check)


def test_r_tui_042a_5_3_64_bit_page(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /3: PAGE64(48) at 80/95/100/118 (*w* = 9/17/20/31)."""
    heads = {80: 4, 95: 8, 100: 9, 118: 15}
    for width, head in heads.items():
        async def _check(app, pilot, table, width=width, head=head):
            geom = _geom(table)
            w = {80: 9, 95: 17, 100: 20, 118: 31}[width]
            assert geom.w == w, (geom.w, w)
            for r in range(table.row_count):
                tag = _tags_of(app, table)[r]
                name = str(tag["name"])
                glyph = "✓" if tag.get("in_memory") else "·"
                cell = table.get_row_at(r)[geom.idx["Tag"]].plain
                assert cell == f"{glyph} " + _shorten(name, w), (r, cell)
                assert cell == f"{glyph} " + name[:head] + "…" + name[len(name) - (w - 1 - head):], (r, cell)
                assert cell.endswith(name[len(name) - (w - 1 - head):]), (r, cell)
                _assert_painted_tag_cell(table, geom, r, cell)

        _explore(tmp_path, page64(48), (width, 54), _check)


def test_r_tui_042a_5_4_fixed_cap_at_220(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /4: LONGMAP(48) then PAGE64(48) at 220 — 36-cell form."""
    async def _long(app, pilot, table):
        geom = _geom(table)
        assert geom.w == 84, geom.w
        cell = table.get_row_at(0)[geom.idx["Tag"]].plain
        assert cell == "✓ " + _shorten(longname(48), 34), cell
        assert cell_len(cell) == 36
        _assert_painted_tag_cell(table, geom, 0, cell)

    async def _p64(app, pilot, table):
        geom = _geom(table)
        assert geom.w == 79, geom.w
        for r in range(table.row_count):
            tag = _tags_of(app, table)[r]
            glyph = "✓" if tag.get("in_memory") else "·"
            cell = table.get_row_at(r)[geom.idx["Tag"]].plain
            assert cell == f"{glyph} " + _shorten(str(tag["name"]), 34), (r, cell)
            assert cell_len(cell) == 36
            _assert_painted_tag_cell(table, geom, r, cell)

    _explore(tmp_path, page_long(48), (220, 60), _long)
    _explore(tmp_path, page64(48), (220, 60), _p64)


def test_r_tui_042a_5_5_narrowest_width(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /5: PAGE64W(48) at 80 (*w* = 5) — 2 + ``…`` + 2."""
    async def _check(app, pilot, table):
        geom = _geom(table)
        assert geom.w == 5, geom.w
        for r in range(table.row_count):
            tag = _tags_of(app, table)[r]
            glyph = "✓" if tag.get("in_memory") else "·"
            cell = table.get_row_at(r)[geom.idx["Tag"]].plain
            assert cell == f"{glyph} " + _shorten(str(tag["name"]), 5), (r, cell)
            _assert_painted_tag_cell(table, geom, r, cell)

    _explore(tmp_path, page64(48, wide16=True), (80, 54), _check)


def _painted_tag_equals(table, row_index: int, want: str) -> bool:
    """Whether the visible Tag span paints ``want`` exactly inside the viewport."""
    result = _painted_tag_cell(table, _geom(table), row_index)
    return result is not None and result[0] == want and result[1] <= _geom(table).visible


def test_r_tui_042a_5_6_resize_resizes_the_tag_cell(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /6: LONGMAP(48) 220×60 → 80×54 → 220×60, no key."""
    async def _check(app, pilot, table):
        wide = "✓ SYN_MAP_LLLLLLLL…LLLLLLLLLLLLL_END"
        narrow = "✓ SYN_MA…LLL_END"
        await wait_until(
            pilot,
            lambda: _all_rows_in_measured_form(app, table) and _painted_tag_equals(table, 0, wide),
            "start painted fit",
            timeout=30,
        )
        geom = _geom(table)
        assert geom.w == 84, geom.w
        _assert_painted_tag_cell(table, geom, 0, wide)
        await pilot.resize_terminal(80, 54)
        await wait_until(
            pilot,
            lambda: _all_rows_in_measured_form(app, table) and _painted_tag_equals(table, 0, narrow),
            "220→80 painted fit",
            timeout=30,
        )
        geom = _geom(table)
        assert geom.w == 14, geom.w
        _assert_painted_tag_cell(table, geom, 0, narrow)
        await pilot.resize_terminal(220, 60)
        await wait_until(
            pilot,
            lambda: _all_rows_in_measured_form(app, table) and _painted_tag_equals(table, 0, wide),
            "80→220 painted fit",
            timeout=30,
        )
        geom = _geom(table)
        assert geom.w == 84, geom.w
        _assert_painted_tag_cell(table, geom, 0, wide)
        assert table.cursor_row == 0

    _explore(tmp_path, page_long(48), (220, 60), _check)


# --- Patch Editor / Save project drive (the R-A2L-048/2 route, E3A-18) -------


def _write_doc(path: Path, entries) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": [
                    {
                        "type": "bytes",
                        "address": f"0x{address:X}",
                        "bytes": " ".join(f"{b:02X}" for b in data),
                    }
                    for address, data in entries
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def _panel(app) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


async def _press_shown(pilot, button: Button) -> None:
    await wait_until(pilot, lambda: button.region.width > 0, f"#{button.id} is not shown")
    button.press()


async def _open_patch(pilot, app) -> None:
    app.set_focus(None)
    await pilot.press("6")
    await wait_until(
        pilot,
        lambda: app._active_screen_key == "patch"
        and len(app.query("#patch_doc_path_input")) > 0
        and app.query_one("#patch_doc_path_input").region.width > 0,
        "the Patch Editor did not show after key 6",
    )
    await _settle(pilot)


async def _load_doc(pilot, app, log, path: Path) -> None:
    mark = len(log.messages)
    p = _panel(app)
    p.query_one("#patch_doc_path_input", Input).value = str(path)
    await _press_shown(pilot, p.query_one("#patch_doc_load_button", Button))
    await wait_until(
        pilot,
        lambda: any(m.startswith("Loaded change:") for m in log.messages[mark:]),
        lambda: f"no 'Loaded change:' for {path.name}: {log.messages[mark:]!r}",
    )
    await _settle(pilot)


async def _apply_loaded(pilot, app, log) -> None:
    mark = len(log.messages)
    await _press_shown(pilot, _panel(app).query_one("#patch_doc_apply_button", Button))
    await wait_until(
        pilot,
        lambda: any(re.match(r"Apply: [1-9]\d* applied", m) for m in log.messages[mark:]),
        lambda: f"no apply line: {log.messages[mark:]!r}",
    )
    await _settle(pilot)


async def _edit_entry(pilot, app, log, address: str, data: str) -> None:
    mark = len(log.messages)
    p = _panel(app)
    p.query_one("#patch_entry_address_input", Input).value = address
    p.query_one("#patch_entry_bytes_input", Input).value = data
    await _press_shown(pilot, p.query_one("#patch_entry_edit_button", Button))
    await wait_until(
        pilot,
        lambda: "Patch Editor: entry updated." in log.messages[mark:],
        lambda: f"entry not updated: {log.messages[mark:]!r}",
    )
    await _settle(pilot)


async def _patch_apply(pilot, app, log, docs: Path, name: str, entries) -> None:
    doc = _write_doc(docs / name, entries)
    await _open_patch(pilot, app)
    await _load_doc(pilot, app, log, doc)
    await _apply_loaded(pilot, app, log)


async def _save_project_commit(pilot, app, log, name: str = "P") -> None:
    mark = len(log.messages)
    await sd.save_through_dialog(pilot, app, name)
    await wait_until(
        pilot,
        lambda: any(m.startswith("Saved project to") for m in log.messages[mark:]),
        lambda: f"no 'Saved project to': {log.messages[mark:]!r}",
    )
    await settle_workers(pilot)
    await _settle(pilot)


def test_r_tui_042a_5_7_save_project_commit_keeps_the_w_form(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /7: LONGMAP(48) at 80×54, one byte applied, the entry
    edited, key 2, then the Save project commit — the repaint keeps 6 + ``…`` + 7."""
    async def _run(app, pilot, log):
        base = Path(app.base_dir)
        a2l = _write_a2l(base, page_long(48))
        await _load(app, pilot, base, a2l)
        await _patch_apply(pilot, app, log, base / "docs", "d.json", [(ADDR, b"\xaa")])
        await _edit_entry(pilot, app, log, f"0x{ADDR:08X}", "55")
        table = await _show_a2l(app, pilot)
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "key 2 fit", timeout=30)
        await _save_project_commit(pilot, app, log)
        # the commit must have written the edited byte, so the repaint after
        # the write is genuinely what is being asserted (not a stale fit).
        assert app.current_file.mem_map.get(ADDR) == 0x55, app.current_file.mem_map.get(ADDR)
        tag_idx = _tag_index(table)
        await wait_until(
            pilot,
            lambda: table.get_row_at(0)[tag_idx].plain == "✓ SYN_MA…LLL_END",
            lambda: f"Tag cell {table.get_row_at(0)[tag_idx].plain!r}",
            timeout=15,
        )
        geom = _geom(table)
        _assert_painted_tag_cell(table, geom, 0, table.get_row_at(0)[tag_idx].plain)

    base = tmp_path / "app"
    base.mkdir(parents=True, exist_ok=True)
    _write_image(base)
    projects.run_app(base, _run, size=(80, 54))


def test_r_tui_042a_5_8_page_build_widens_the_address_column(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /8: MANY(230, 48) with MEASUREMENT 215 at the 64-bit
    address, 80×54 — ``plus`` then ``minus``; the Address column 12 → 16 and
    every Tag cell in the *w* = 8 form on both pages."""
    async def _check(app, pilot, table):
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "page 1 fit", timeout=30)
        geom = _geom(table)
        assert geom.cols[0][1] == 12, geom.cols[0][1]
        assert geom.w == 12, geom.w
        _assert_all_rows_form_and_inside(app, table, geom, 12)
        await pilot.press("plus")
        await wait_until(pilot, lambda: app._a2l_window_start == 200, "page 2")
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "page 2 fit", timeout=30)
        assert table.row_count == 31, table.row_count
        geom = _geom(table)
        assert geom.cols[0][1] == 16, geom.cols[0][1]
        assert geom.w == 8, geom.w
        _assert_all_rows_form_and_inside(app, table, geom, 8)
        await pilot.press("minus")
        await wait_until(pilot, lambda: app._a2l_window_start == 0, "back to page 1")
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "page 1 fit after", timeout=30)
        assert table.row_count == 200, table.row_count
        geom = _geom(table)
        assert geom.cols[0][1] == 16, "the Address column must stay 16 (E2-4)"
        assert geom.w == 8, geom.w
        _assert_all_rows_form_and_inside(app, table, geom, 8)

    _explore(tmp_path, page_many(230, 48, wide_at=215), (80, 54), _check)


def test_r_tui_042a_5_9_page_build_drops_the_vertical_scrollbar(tmp_path: Path) -> None:
    """R-TUI-042a.5 case /9: MANY(219, 48) at 80×54 — page 1 *w* = 12 with the
    scrollbar, page 2 *w* = 14 without it, back to page 1 *w* = 12."""
    async def _check(app, pilot, table):
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "page 1 fit", timeout=30)
        geom = _geom(table)
        assert geom.w == 12, geom.w
        assert table.show_vertical_scrollbar, "page 1 must show a vertical scrollbar"
        _assert_all_rows_form_and_inside(app, table, geom, 12)
        await pilot.press("plus")
        await wait_until(pilot, lambda: app._a2l_window_start == 200, "page 2")
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "page 2 fit", timeout=30)
        assert table.row_count == 20, table.row_count
        geom = _geom(table)
        assert geom.w == 14, geom.w
        assert not table.show_vertical_scrollbar, "page 2 must drop the vertical scrollbar"
        _assert_all_rows_form_and_inside(app, table, geom, 14)
        await pilot.press("minus")
        await wait_until(pilot, lambda: app._a2l_window_start == 0, "back to page 1")
        await wait_until(pilot, lambda: _all_rows_in_measured_form(app, table), "page 1 fit after", timeout=30)
        assert table.row_count == 200, table.row_count
        geom = _geom(table)
        assert geom.w == 12, geom.w
        _assert_all_rows_form_and_inside(app, table, geom, 12)

    _explore(tmp_path, page_many(219, 48), (80, 54), _check)


# ---------------------------------------------------------------------------
# R-TUI-042a.6 — U+FFFD before the cut, O(*w*)
# ---------------------------------------------------------------------------


def _build_cell(tmp_path: Path, name: str, width: int):
    """One ``_build_a2l_table_cells(tag, width)`` call on an app rooted at
    ``tmp_path/app``; returns (cell_text, elapsed_seconds)."""
    base = tmp_path / "app"
    base.mkdir(parents=True, exist_ok=True)
    app = S19TuiApp(base_dir=base)
    start = time.perf_counter()
    cells = app._build_a2l_table_cells({"name": name, "in_memory": True}, width)
    return cells[2].plain, time.perf_counter() - start


@pytest.mark.serial_timing
def test_r_tui_042a_6_1_zero_width_tail(tmp_path: Path) -> None:
    """R-TUI-042a.6 case /1: a 47-char ASCII name + 4,000 then 16,000 × U+200B —
    one ``_build_a2l_table_cells(tag, 14)`` call each, under 1 s, 6 + ``…`` + 7 × U+FFFD."""
    for tail_len in (4_000, 16_000):
        plain, elapsed = _build_cell(tmp_path, "A" * 47 + "\u200b" * tail_len, 14)
        assert elapsed < 1.0, elapsed
        report_margin("R-TUI-042a.6/1 cell build", elapsed, 1.0)
        assert plain == "✓ " + "A" * 6 + "…" + "\ufffd" * 7, plain


@pytest.mark.serial_timing
def test_r_tui_042a_6_2_combining_and_esc_tails(tmp_path: Path) -> None:
    """R-TUI-042a.6 case /2: the same name + 16,000 × U+0301, then + 16,000 × ESC —
    the /1 form, no U+0301 and no ESC in the cell."""
    for tail_char in ("\u0301", "\x1b"):
        plain, elapsed = _build_cell(tmp_path, "A" * 47 + tail_char * 16_000, 14)
        assert elapsed < 1.0, elapsed
        report_margin("R-TUI-042a.6/2 cell build", elapsed, 1.0)
        assert plain == "✓ " + "A" * 6 + "…" + "\ufffd" * 7, plain
        assert "\u0301" not in plain and "\x1b" not in plain, repr(plain)


def test_r_tui_042a_6_3_plain_ascii_unchanged(tmp_path: Path) -> None:
    """R-TUI-042a.6 case /3: LONGMAP(48)'s ASCII name — ``✓ SYN_MA…LLL_END``,
    no U+FFFD; a raw name ``"A "`` at width 2 — ``✓ A�`` (the trailing space
    projected to U+FFFD, not stripped)."""
    plain, _elapsed = _build_cell(tmp_path, longname(48), 14)
    assert plain == "✓ SYN_MA…LLL_END", plain
    assert "\ufffd" not in plain, repr(plain)
    # Discriminating arm: a trailing space (U+0020, outside U+0021..U+007E)
    # must project to U+FFFD, not be stripped — a strip would leave ``✓ A``.
    projected, _elapsed = _build_cell(tmp_path, "A ", 2)
    assert projected == "✓ A\ufffd", projected


# ---------------------------------------------------------------------------
# R-TUI-042a.7.1 / .7.2 / .8 — the detail card is a safe-text view
# ---------------------------------------------------------------------------


#: A minimal self-contained A2L wrapper for the hostile-card fixtures.
_CARD_HEAD = (
    "ASAP2_VERSION 1 71\n"
    "/begin PROJECT PCARD \"\"\n"
    "/begin MODULE MCARD \"\"\n"
    "/begin MOD_COMMON \"\"\n"
    "BYTE_ORDER MSB_LAST\n"
    "/end MOD_COMMON\n"
)
_CARD_TAIL = "/end MODULE\n/end PROJECT\n"

#: The CHARACTERISTIC variant also declares a COMPU_METHOD and a RECORD_LAYOUT
#: so the limits case stacks header, desc, unit·conv, layout and byteorder
#: above its limits line.
_CARD_HEAD_CHAR = (
    _CARD_HEAD
    + '/begin COMPU_METHOD CM_SYN "" IDENTICAL "%.0" ""\n'
    + "/end COMPU_METHOD\n"
    + "/begin RECORD_LAYOUT RL_SYN\n"
    + "FNC_VALUES 1 UWORD COLUMN_DIR DIRECT\n"
    + "/end RECORD_LAYOUT\n"
)


def _card_measurement(
    name: str = "SYN_NAME",
    desc: Optional[str] = None,
    *,
    display_identifier: Optional[str] = None,
    unit: Optional[str] = None,
    conversion: Optional[str] = None,
) -> str:
    """A one-MEASUREMENT synthetic A2L (``ECU_ADDRESS 0x1000``, 2 bytes) whose
    detail card shows the given file-derived values — each value travels the
    real A2L reader, enrichment and card renderer."""
    lines = [f'/begin MEASUREMENT {name} "{desc or ""}"']
    lines.append("  ECU_ADDRESS 0x1000")
    lines.append("  DATA_SIZE 2")
    if display_identifier is not None:
        lines.append(f"  DISPLAY_IDENTIFIER {display_identifier}")
    if unit is not None:
        lines.append(f'  UNIT "{unit}"')
    if conversion is not None:
        lines.append(f"  COMPU_METHOD {conversion}")
    lines.append("/end MEASUREMENT")
    return _CARD_HEAD + "\n".join(lines) + "\n" + _CARD_TAIL


def _card_characteristic_limits(
    lower_limit: str, upper_limit: str, *, unit: str = "u"
) -> str:
    """A one-VALUE CHARACTERISTIC whose card stacks header, desc, unit·conv,
    layout and byteorder above the limits line — so the limits sit below the
    card's 5 visible rows and must be scrolled into view (R-TUI-042a.7.1/6)."""
    lines = [
        '/begin CHARACTERISTIC SYN_NAME "d"',
        f"  VALUE 0x1000 RL_SYN 0 CM_SYN {lower_limit} {upper_limit}",
        f'  UNIT "{unit}"',
        "/end CHARACTERISTIC",
    ]
    return _CARD_HEAD_CHAR + "\n".join(lines) + "\n" + _CARD_TAIL


def _screen_output(app) -> str:
    """The raw terminal sequence Textual builds for the driver (what
    ``App._display`` writes), per E3S-02 / the E3S probe."""
    return app.screen._compositor.render_full_update().render_segments(app.console)


def _explore_card(tmp_path: Path, a2l_text: str, size: tuple[int, int], scenario) -> None:
    """Boot the app, load a 2-byte 0x1000 image + the hostile A2L through the
    real loader, show the Explorer with the cursor on row 0, then run
    ``scenario(app, pilot, table)``."""
    base = tmp_path / "app"
    base.mkdir(parents=True, exist_ok=True)
    img = base / "syn_img.s19"
    img.write_text(
        emit_s19_from_mem_map({0x1000: 0x00, 0x1001: 0x00}, [(0x1000, 0x1002)]),
        encoding="ascii",
    )
    a2l = _write_a2l(base, a2l_text)

    async def _run(app, pilot, log):
        await _load(app, pilot, base, a2l)
        table = await _show_a2l(app, pilot)
        await scenario(app, pilot, table)

    projects.run_app(base, _run, size=size)


def _assert_card_lines_clean(plain: str) -> None:
    for line in plain.split("\n"):
        assert not any(ord(ch) in _CONTROL for ch in line), repr(line)


async def _assert_card_painted_then_safe(
    app, pilot, projected: str, *, scroll: bool = False
) -> None:
    """Positive-first (R-TUI-042a.7.1): prove ``projected`` — the value's
    control-free projection — is actually painted (scrolling to the end with an
    asserted nonzero effective scroll first when it lives below the card's
    visible rows), then every card text line holds no control character and the
    screen output holds none of the four hostile introducers."""
    card = _card(app)
    if scroll:
        full = card.render().plain
        assert "byteorder " in full, full
        assert "limits " in full, full
        assert card.max_scroll_y > 0, card.max_scroll_y
        card.scroll_to(y=card.max_scroll_y, animate=False, force=True, immediate=True)
        await _settle(pilot, 6)
        assert card.scroll_y > 0, (card.scroll_y, card.max_scroll_y)
        screen = _screen_output(app)
        painted = Text.from_ansi(screen).plain
        assert projected in painted, (projected, painted)
        _assert_card_lines_clean(full)
        _assert_no_introducers(screen)
        return
    painted = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
    joined = "".join(painted)
    assert projected in joined, (projected, joined)
    _assert_card_lines_clean(card.render().plain)
    _assert_no_introducers(_screen_output(app))


def _assert_no_introducers(seq: str) -> None:
    for intro in _INTRODUCER_SEQS:
        assert intro not in seq, intro


def test_r_tui_042a_7_1_1_name_without_display_identifier(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /1: a hostile name, no DISPLAY_IDENTIFIER, loaded
    from a real A2L file — the projected name is painted in the card header
    before the hostile introducers are asserted absent from the screen output."""
    name, scrubbed = _hostile("SYN", "_END")
    a2l = _card_measurement(name=name)

    async def _observe(app, pilot, table):
        await _assert_card_painted_then_safe(app, pilot, scrubbed)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_1_2_display_identifier(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /2: a hostile DISPLAY_IDENTIFIER word, from a real
    A2L file."""
    disp, scrubbed = _hostile("SYN", "_DISP")
    a2l = _card_measurement(name="SYN_NAME", display_identifier=disp)

    async def _observe(app, pilot, table):
        await _assert_card_painted_then_safe(app, pilot, scrubbed)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_1_3_description(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /3: a hostile description (the long identifier),
    from a real A2L file."""
    desc, scrubbed = _hostile("DESC_", "_END")
    a2l = _card_measurement(name="SYN_NAME", desc=desc)

    async def _observe(app, pilot, table):
        await _assert_card_painted_then_safe(app, pilot, scrubbed)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_1_4_unit(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /4: a hostile unit (a quoted string), from a real
    A2L file."""
    unit, scrubbed = _hostile("m", "_u")
    a2l = _card_measurement(name="SYN_NAME", unit=unit)

    async def _observe(app, pilot, table):
        await _assert_card_painted_then_safe(app, pilot, scrubbed)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_1_5_conversion(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /5: a hostile conversion word (``COMPU_METHOD``),
    from a real A2L file."""
    conv, scrubbed = _hostile("CV_", "_END")
    a2l = _card_measurement(name="SYN_NAME", conversion=conv)

    async def _observe(app, pilot, table):
        await _assert_card_painted_then_safe(app, pilot, scrubbed)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_1_6_limits(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /6: a hostile lower-limit word, then a hostile
    upper-limit word — each loaded from a real A2L file; the limits line sits
    below the card's 5 visible rows and is scrolled into view, proven painted,
    before the hostile introducers are asserted absent."""
    for field in ("lower_limit", "upper_limit"):
        hostile, scrubbed = _hostile("LIM", "_END")
        if field == "lower_limit":
            a2l = _card_characteristic_limits(lower_limit=hostile, upper_limit="100")
        else:
            a2l = _card_characteristic_limits(lower_limit="0", upper_limit=hostile)

        async def _observe(app, pilot, table, scrubbed=scrubbed):
            await _assert_card_painted_then_safe(app, pilot, scrubbed, scroll=True)

        _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_1_7_name_on_the_name_line(tmp_path: Path) -> None:
    """R-TUI-042a.7.1 case /7: a clean display identifier, a hostile name — the
    first line shows ``SYN_DISP_C``, the painted Name line and its continuations
    hold the projected name, and the screen output holds none of the four
    hostile introducers."""
    name, scrubbed = _hostile("SYN", "_END")
    a2l = _card_measurement(name=name, display_identifier="SYN_DISP_C")

    async def _observe(app, pilot, table):
        card = _card(app)
        lines = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
        assert lines and lines[0].startswith("✓ SYN_DISP_C"), lines
        start = next((i for i, ln in enumerate(lines) if ln == "name" or ln.startswith("name ")), None)
        assert start is not None, lines
        assert scrubbed in "".join(lines[start:]), (scrubbed, lines[start:])
        _assert_card_lines_clean(card.render().plain)
        _assert_no_introducers(_screen_output(app))

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_2_1_description_break_run(tmp_path: Path) -> None:
    """R-TUI-042a.7.2 case /1: a long identifier written over two lines, the
    second starting with a TAB — the painted desc line reads
    ``desc SYN  desc part two`` and no TAB/LF/CR from the value is painted or
    sent to the terminal."""
    a2l = (
        _CARD_HEAD
        + '/begin MEASUREMENT SYN_NAME "SYN  desc\n\tpart two"\n'
        + "  ECU_ADDRESS 0x1000\n"
        + "  DATA_SIZE 2\n"
        + "/end MEASUREMENT\n"
        + _CARD_TAIL
    )

    async def _observe(app, pilot, table):
        card = _card(app)
        lines = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
        joined = "".join(lines)
        assert "desc SYN  desc part two" in joined, joined
        plain = card.render().plain
        assert "\t" not in plain and "\r" not in plain, repr(plain)
        _assert_no_introducers(_screen_output(app))
        assert "\t" not in _screen_output(app)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_7_2_2_unit_break_run(tmp_path: Path) -> None:
    """R-TUI-042a.7.2 case /2: a unit ``m`` + TAB + TAB + ``s`` — the painted
    unit line starts ``unit m s`` and no TAB from the value is painted or sent
    to the terminal."""
    a2l = _card_measurement(name="SYN_NAME", unit="m\t\ts")

    async def _observe(app, pilot, table):
        card = _card(app)
        lines = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
        joined = "".join(lines)
        assert "unit m s" in joined, joined
        assert "\t" not in card.render().plain, repr(card.render().plain)
        assert "\t" not in _screen_output(app)

    _explore_card(tmp_path, a2l, (118, 54), _observe)


def test_r_tui_042a_8_1_name_line_with_a_display_identifier(tmp_path: Path) -> None:
    """R-TUI-042a.8 case /1: LONGMAP(48) with ``DISPLAY_IDENTIFIER SYN_DISP_W`` —
    first line ``✓ SYN_DISP_W  0x1C2D3E00``; the painted Name line and its
    painted continuations hold the full 48-character name (never read from
    ``card.render().plain``)."""
    async def _check(app, pilot, table):
        card = _card(app)
        lines = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
        assert lines and lines[0] == f"✓ SYN_DISP_W  {ADDR_STR}", lines
        start = next((i for i, ln in enumerate(lines) if ln == "name" or ln.startswith("name ")), None)
        assert start is not None, lines
        assert longname(48) in "".join(lines[start:]), (longname(48), lines[start:])

    _explore(tmp_path, HEAD + map_block(longname(48), display_identifier="SYN_DISP_W") + TAIL,
             (118, 54), _check)


def test_r_tui_042a_8_2_no_name_line_without_a_display_identifier(tmp_path: Path) -> None:
    """R-TUI-042a.8 case /2: LONGMAP(48) with no display identifier — the header
    holds the name across the wrap, and no line starts with ``name``."""
    async def _check(app, pilot, table):
        card = _card(app)
        lines = [ln.rstrip() for ln in _painted_lines(card) if ln.strip()]
        joined = "".join(lines)
        assert longname(48) in joined, (longname(48), joined)
        plain = card.render().plain
        assert not any(ln.startswith("name ") for ln in plain.split("\n")), plain

    _explore(tmp_path, page_long(48), (118, 54), _check)


# ---------------------------------------------------------------------------
# AT-B103-I12-1 — no glued or cut values at every width and page
# ---------------------------------------------------------------------------


def _assert_at_invariants(app, table, declared_addrs: set, declared_lengths: set) -> None:
    geom = _geom(table)
    tag_idx = geom.idx["Tag"]
    for line in _painted_lines(table):
        for run in _hex_runs(line):
            assert run in declared_addrs, (run, declared_addrs)
    for line in _painted_lines(_card(app)):
        for run in _hex_runs(line):
            assert run in declared_addrs, (run, declared_addrs)
    for r in range(table.row_count):
        cells = table.get_row_at(r)
        assert cells[0].plain in declared_addrs, (r, cells[0].plain)
        assert cells[1].plain in declared_lengths, (r, cells[1].plain)
        assert _cell_whole_in_painted(table, geom, r, 0), r
        assert _cell_whole_in_painted(table, geom, r, 1), r
        _assert_painted_tag_cell(table, geom, r, cells[tag_idx].plain)


def test_at_b103_i12_1_no_glued_or_cut_values(tmp_path: Path) -> None:
    """AT-B103-I12-1: SYNMAP at 220/160/118/100/80; LONGMAP(48) at 118; PAGE64(48)
    loaded while the Explorer is shown at 80 and 118 — every ``0x…`` run is a
    declared address, every Length cell a declared length, every Tag cell ends
    inside the visible width, and the SYNMAP card's first line is
    ``✓ SYN_MAP_W  0x1C2D3E00``."""
    syn_declared = {ADDR_STR}
    syn_lengths = {"2266"}

    for width in (220, 160, 118, 100, 80):
        async def _syn(app, pilot, table):
            _assert_at_invariants(app, table, syn_declared, syn_lengths)
            lines = [ln.rstrip() for ln in _painted_lines(_card(app)) if ln.strip()]
            assert lines and lines[0] == f"✓ SYN_MAP_W  {ADDR_STR}", lines

        _explore(tmp_path, page_syn(), (width, 50), _syn)

    async def _long(app, pilot, table):
        _assert_at_invariants(app, table, {ADDR_STR}, {"2266"})

    _explore(tmp_path, page_long(48), (118, 54), _long)

    p64_declared = {ADDR_STR, ADDR64_STR, ADDR_0x1000_STR}
    p64_lengths = {"2266", "2", "1048576"}

    for width in (80, 118):
        async def _p64_reload(app, pilot, table):
            # load PAGE64 while the Explorer is shown (a distinct file name, so
            # the reload is a fresh copy, not a re-parse of the SYNMAP file)
            base = Path(app.base_dir)
            app.load_a2l_from_path(_write_a2l(base, page64(48), name="page64.a2l"))
            await settle_workers(pilot)
            await wait_until(pilot, lambda: _tag_table(app).row_count == 3, "PAGE64 rows", timeout=30)
            await wait_until(pilot, lambda: _all_rows_in_measured_form(app, _tag_table(app)),
                             "PAGE64 fit", timeout=30)
            _assert_at_invariants(app, _tag_table(app), p64_declared, p64_lengths)

        _explore(tmp_path, page_syn(), (width, 54), _p64_reload)
