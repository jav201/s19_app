"""Batch-103 Inc 9 E4, group B - the bench render, part 2: the bench detail, the bytes line, the op line.

Design under test: ``.dev-flow/2026-11-05-batch-103/inc-9/01-requirements.md`` (rows R-PE-BENCH.3, .4, .5, .7,
.21, .38, .39, .50, .66, .90, .91, .93) through ``s19_app/tui/definition_bench_view.py`` (new): nodes B14
``bench_detail``, B21 ``bytes_line``, B22 ``op_line``. One test per case of ``inc-9/02-test-cases-B.md``.

``bench_detail(row, preview, width, state, room)`` is Inc 8's ``KindOps.detail`` (the row is Inc 8's
``build_row`` over the definition). Its first line is Inc 8's definition line, then the canvas, the legend, the
tool row and the bytes line. ``op_line(row, state, width)`` answers ``(name, tail)``. Expected texts are the
requirement's own, or are computed by I-2 (real encodes) and the example oracle ``EX``.
"""

from __future__ import annotations

import dataclasses
import re

import pytest
from rich.cells import cell_len

from s19_app.tui import definition_bench as db
from s19_app.tui import definition_bench_view as dv
from s19_app.tui import definition_sheet as ds
from s19_app.tui.screens_directionb.patch_editor import bench_sheet  # noqa: F401  (registers the bench kinds' KindOps)
from s19_app.tui.a2l_definition import Encoded, Refusal, encode_values
from tests.support.b103_inc8b_r import BAR, content
from tests.support.b103_inc9_b import (  # noqa: F401  (fixtures are used by name)
    FFFD,
    big_values,
    blank_state,
    defc,
    defc_obj,
    large_definition,
    linked,
    max_cells,
    plain_of,
    runs_of,
    sheet_row,
    view_state,
)

DEFINITION_LINE_VB = "└ LINEAR phys = 0.05*raw · SWORD s16 big-endian · RL_DEF_S16_ROW · 0x00800090 · 12 B"
NO_EDIT = "no edit yet · bytes appear here"


def detail(o, state, width=114, room=50, preview=None):
    row = sheet_row(o.d, o.a2l, o.image)
    return dv.bench_detail(row, preview, width, state, room)


def large_case(tmp_path):
    """(row, state) of LARGE with a compact window of zeros; never decoded by I-2."""
    a2l, d = large_definition(tmp_path)
    grid = db.bench_grid(d)
    values = big_values(grid.count)
    state = blank_state(values=values, labels=dv.axis_labels(d, (), grid))
    return sheet_row(d, a2l, {}), state


def tail_of(o, state, width=118):
    row = sheet_row(o.d, o.a2l, o.image)
    return dv.op_line(row, state, width)


# ==========================================================================
# B14 bench_detail - R-PE-BENCH.3, .4
# ==========================================================================


@pytest.mark.parametrize("name", ["CURVE_DEF_0001", "MAP_DEF_0001", "VAL_BLK_DEF_0001"])
def test_r_pe_bench_3_the_bench_lines_come_in_order(defc, name):
    """R-PE-BENCH.3/1..3 - CURVE / MAP / VAL_BLK: definition line, canvas, legend line, tool row, bytes line, in that order."""
    o = defc_obj(defc, name)
    plains = [p.rstrip() for p in plain_of(detail(o, view_state(o)))]
    legend = next(i for i, p in enumerate(plains) if p.lstrip().startswith(("shade ", "scale ")))
    tools = next(i for i, p in enumerate(plains) if "Interpolate" in p)
    assert plains[0].startswith("└ ")
    assert 1 <= legend - 1, "at least one canvas line between the definition line and the legend"
    assert legend < tools < len(plains) - 1
    assert plains[-1].strip() == NO_EDIT
    assert sum(1 for p in plains if "Interpolate" in p) == 1


def test_r_pe_bench_4_1_the_definition_line_of_an_array(defc):
    """R-PE-BENCH.4/1 - VAL_BLK_DEF_0001: `└ LINEAR phys = 0.05*raw · SWORD s16 big-endian · RL_DEF_S16_ROW · 0x00800090 · 12 B`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert detail(o, view_state(o))[0].plain.strip() == DEFINITION_LINE_VB


@pytest.mark.parametrize("name, tail", [("MAP_DEF_0001", " · RL_DEF_MAP · 0x00800070 · 32 B"),
                                         ("CURVE_DEF_0001", " · RL_U16 · 0x00800050 · 10 B")])
def test_r_pe_bench_4_2_3_the_layout_follows_the_byte_order(defc, name, tail):
    """R-PE-BENCH.4/2,3 - MAP_DEF_0001 `… · RL_DEF_MAP · 0x00800070 · 32 B`; CURVE_DEF_0001 `… · RL_U16 · 0x00800050 · 10 B`."""
    o = defc_obj(defc, name)
    first = detail(o, view_state(o))[0].plain.strip()
    assert first.startswith("└ ") and first.endswith(tail)
    assert first.index("big-endian") < first.index(o.d.record_layout), "the layout comes after the byte order"


# ==========================================================================
# B14 bench_detail - R-PE-BENCH.5, .7, .21
# ==========================================================================


def through_sheet(row, state, view, room):
    """The expanded object the sheet paints for a bench row: ``detail_lines`` at the view width V (Inc 8b, R-PE-DEF.107)."""
    return ds.detail_lines(row, None, view, state, room)


@pytest.mark.parametrize("view", [73, 111, 195])
def test_r_pe_bench_5_1_2_3_no_bench_line_is_wider_than_the_sheet(defc, tmp_path, view):
    """R-PE-BENCH.5/1..3 (changed at Inc 8b E1) - at 80, 118 and 220 columns (V = 73, 111, 195): MAP_DEF_0001 and LARGE.

    Why: the sheet lays the bench out for V - 4 cells (so its canvas never needs the grid's horizontal
    scroll) and the expanded ground pads each line to max(143, V); the content, once that ground is
    trimmed, is the bar plus at most V - 4 cells. Laying the bench out for the 139-cell card cap would put
    LARGE at 80 columns 66 cells off screen.
    """
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = detail(o, view_state(o), width=view - 4, room=50)
    assert lines and max_cells(lines) <= view - 4, "the kind's own contract: its width is V - 4"
    big_row, big_state = large_case(tmp_path)
    assert dv.bench_detail(big_row, None, view - 4, big_state, 50)
    for row, state in ((sheet_row(o.d, o.a2l, o.image), view_state(o)), (big_row, big_state)):
        painted = through_sheet(row, state, view, 50)
        assert painted and all(t.plain.startswith(BAR) for t in painted), "every expanded line carries the bar"
        assert max(cell_len(t.plain.rstrip()) for t in painted) <= view, "once the ground is trimmed: bar + V - 4"
        assert content(painted[0].plain).startswith("└ ")


def test_r_pe_bench_5_4_room_one_shows_the_definition_line_only(defc, tmp_path):
    """R-PE-BENCH.5/4 - room 1: MAP_DEF_0001 and LARGE give exactly the definition line (after the bar), no exception."""
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = detail(o, view_state(o), room=1)
    assert len(lines) == 1 and lines[0].plain.startswith("└ ")
    big_row, big_state = large_case(tmp_path)
    big = dv.bench_detail(big_row, None, 114, big_state, 1)
    assert len(big) == 1 and big[0].plain.startswith("└ ")
    for row, state in ((sheet_row(o.d, o.a2l, o.image), view_state(o)), (big_row, big_state)):
        painted = through_sheet(row, state, 111, 1)
        assert len(painted) == 1 and content(painted[0].plain).startswith("└ ")


def test_r_pe_bench_5_5_room_zero_shows_no_bench_line(defc, tmp_path):
    """R-PE-BENCH.5/5 - room 0: MAP_DEF_0001 and LARGE give no line at all, through the kind and through the sheet."""
    o = defc_obj(defc, "MAP_DEF_0001")
    assert detail(o, view_state(o), room=0) == []
    big_row, big_state = large_case(tmp_path)
    assert dv.bench_detail(big_row, None, 114, big_state, 0) == []
    assert through_sheet(big_row, big_state, 111, 0) == []
    assert through_sheet(sheet_row(o.d, o.a2l, o.image), view_state(o), 111, 0) == []


@pytest.mark.parametrize("name", ["MAP_DEF_0001", "CURVE_DEF_0001", "VAL_BLK_DEF_0001"])
def test_r_pe_bench_5_no_more_bench_lines_than_the_room(defc, name):
    """R-PE-BENCH.5 (negative control: chart height max(4, ...)) - rooms 0 .. 12: at most `room` lines, never an exception."""
    o = defc_obj(defc, name)
    for room in range(0, 13):
        assert len(detail(o, view_state(o), room=room)) <= room, (name, room)


@pytest.mark.parametrize("width", [10, 0])
def test_r_pe_bench_7_1_2_a_map_under_the_bench_minimum_width(defc, width):
    """R-PE-BENCH.7/1,2 - MAP_DEF_0001 at content width 10 / 0: the definition line only, <= width cells, `…`; width 0: one empty line."""
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = detail(o, view_state(o), width=width)
    assert len(lines) == 1
    assert cell_len(lines[0].plain) <= width
    if width:
        assert lines[0].plain.endswith("…") and lines[0].plain.count("…") == 1
    else:
        assert lines[0].plain == ""


@pytest.mark.parametrize("width", [10, 0])
def test_r_pe_bench_7_3_4_large_under_the_bench_minimum_width(tmp_path, width):
    """R-PE-BENCH.7/3,4 - LARGE at content width 10 / 0: the same."""
    row, state = large_case(tmp_path)
    lines = dv.bench_detail(row, None, width, state, 50)
    assert len(lines) == 1 and cell_len(lines[0].plain) <= width
    assert (lines[0].plain.endswith("…") and lines[0].plain.count("…") == 1) if width else lines[0].plain == ""


def test_r_pe_bench_7_the_bench_minimum_width_is_twelve(defc):
    """R-PE-BENCH.7 / EX-W2 - at content width 12 the grid fits (more than the definition line); at 11 only the definition line."""
    o = defc_obj(defc, "MAP_DEF_0001")
    assert len(detail(o, view_state(o), width=11)) == 1
    assert len(detail(o, view_state(o), width=12)) > 1


def test_r_pe_bench_21_1_a_decoding_row_says_so_in_place_of_the_canvas(tmp_path):
    """R-PE-BENCH.21/1 - LARGE while its decode runs: the line after the definition line is `decoding 1048576 values …`."""
    a2l, d = large_definition(tmp_path)
    row = sheet_row(d, a2l, {})
    lines = dv.bench_detail(row, None, 114, blank_state(job="decode"), 50)
    assert lines[1].plain.strip() == "decoding 1048576 values …"
    assert lines[0].plain.startswith("└ ")


def test_r_pe_bench_21_a_refused_decode_says_refused_not_decoding(tmp_path):
    """FX9b W-8 (X9 F-X9-4, capture `x-refused-decode`): once the decode is refused, `decoding <n> values …` would
    state a decode that no longer runs, so the operator waits for values that never come. The line says
    `✗ refused: <message>`, the message painted literally (markup off, controls cleaned, as the bytes line). A new
    decode of the row (job "decode" again) shows the decoding line again (control)."""
    a2l, d = large_definition(tmp_path)
    row = sheet_row(d, a2l, {})
    refusal = Refusal("A2L-DEF-BYTES", "[b]LARGE[/b] needs\x1b 1048576 bytes")
    lines = dv.bench_detail(row, None, 114, blank_state(refusal=refusal, job=None), 50)
    assert lines[1].plain == "✗ refused: [b]LARGE[/b] needs� 1048576 bytes"
    assert not any("decoding" in line.plain for line in lines)
    again = dv.bench_detail(row, None, 114, blank_state(refusal=refusal, job="decode"), 50)
    assert again[1].plain.strip() == "decoding 1048576 values …"


# ==========================================================================
# B21 bytes_line - R-PE-BENCH.38, .39
# ==========================================================================


def _record_runs(o, edit):
    enc = encode_values(o.d, o.a2l, edit, o.image)
    assert isinstance(enc, Encoded), enc
    old = bytes(o.image[o.d.address + i] for i in range(o.d.byte_length))
    return enc, runs_of(old, bytes(enc.data))


def test_r_pe_bench_38_1_no_edit(defc):
    """R-PE-BENCH.38/1 - no edit -> `no edit yet · bytes appear here`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    assert dv.bytes_line(o.d, (), None, 114).plain.strip() == NO_EDIT


def test_r_pe_bench_38_2_one_changed_run(defc):
    """R-PE-BENCH.38/2 - VAL_BLK_DEF_0001 Set 10 on (0,0): `2 of 12 B differ  +0x00 02 E1 → 00 C8`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    enc, runs = _record_runs(o, {(0, 0): "10"})
    assert dv.bytes_line(o.d, runs, enc, 114).plain.strip() == "2 of 12 B differ  +0x00 02 E1 → 00 C8"


def test_r_pe_bench_38_3_two_cells_make_one_run_of_four_bytes(defc):
    """R-PE-BENCH.38/3 - +Δ 5 on (0,0), (1,0): `4 of 12 B differ  +0x00 02 E1 00 DB → 03 46 01 40`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    enc, runs = _record_runs(o, {(0, 0): "41.9", (1, 0): "16.0"})
    assert dv.bytes_line(o.d, runs, enc, 114).plain.strip() == "4 of 12 B differ  +0x00 02 E1 00 DB → 03 46 01 40"


def test_r_pe_bench_38_a_second_run_is_listed_in_record_order(defc):
    """R-PE-BENCH.38 - MAP_DEF_0001 +Δ 100 (EX-M2): `6 of 32 B differ` with the runs at offsets 8, 15 and 17 in record order."""
    o = defc_obj(defc, "MAP_DEF_0001")
    enc, runs = _record_runs(o, {(0, 0): "572", (1, 0): "232", (0, 1): "809", (1, 1): "-790"})
    text = dv.bytes_line(o.d, runs, enc, 200).plain.strip()
    assert text.startswith("6 of 32 B differ  ")
    offsets = [text.index(f"+0x{off:02X} ") for off, _old, _new in runs]
    assert [run[0] for run in runs] == [8, 15, 17], "the changed bytes 8..11, 15 and 17 are three runs"
    assert offsets == sorted(offsets)


def test_r_pe_bench_38_4_a_refused_preview(defc):
    """R-PE-BENCH.38/4 - Set 60: `✗ refused: VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    refusal = encode_values(o.d, o.a2l, {(0, 0): "60"}, o.image)
    assert isinstance(refusal, Refusal)
    got = dv.bytes_line(o.d, (), refusal, 114).plain.strip()
    assert got == "✗ refused: VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50"


@pytest.mark.parametrize("width", [76, 114])
def test_r_pe_bench_39_1_2_a_long_bytes_line_is_cut_with_an_ellipsis(tmp_path, width):
    """R-PE-BENCH.39/1,2 - LARGE, Set on 64 cells spaced 2 apart, at 80 / 118 columns (76 / 114): ends `…` and fits."""
    a2l, d = large_definition(tmp_path)
    runs = tuple((2 * i, b"\x00", b"\x07") for i in range(64))
    enc = Encoded(d.address, bytes(d.byte_length), ())
    plain = dv.bytes_line(d, runs, enc, width).plain
    assert plain.rstrip().endswith("…") and plain.count("…") == 1
    assert cell_len(plain) <= width


# ==========================================================================
# B22 op_line - R-PE-BENCH.50, .66, .90, .91, .93
# ==========================================================================


def test_r_pe_bench_50_1_the_map_op_line(defc):
    """R-PE-BENCH.50/1 - MAP_DEF_0001 selection x0..1, y0..1, tool +Δ: `MAP_DEF_0001[x0..1,y0..1]` ... `+Δ on 4 cells`."""
    o = defc_obj(defc, "MAP_DEF_0001")
    name, tail = tail_of(o, view_state(o, cursor=(1, 1), anchor=(0, 0), tool="d"))
    assert name == "MAP_DEF_0001[x0..1,y0..1]"
    assert "+Δ on 4 cells" in tail.plain


def test_r_pe_bench_50_2_the_curve_op_line(defc):
    """R-PE-BENCH.50/2 - CURVE_DEF_0001 point 3, tool Set: `CURVE_DEF_0001[3]` ... `Set on 1 pts`."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    name, tail = tail_of(o, view_state(o, cursor=(3, 0), anchor=(3, 0), tool="s"))
    assert name == "CURVE_DEF_0001[3]"
    assert re.search(r"Set on 1 pt(?!s)", tail.plain), tail.plain  # FX9b F-X9-7: k = 1 is singular


def test_r_pe_bench_50_3_the_unit_follows_the_input(defc):
    """R-PE-BENCH.50/3 - VAL_BLK_DEF_0001: the unit `units` opens the tail; the tool label follows it."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    _name, tail = tail_of(o, view_state(o, tool="p"))
    assert tail.plain.lstrip().startswith("units")
    assert re.search(r"×% on 1 cell(?!s)", tail.plain), tail.plain  # FX9b F-X9-7: k = 1 is singular
    assert tail.plain.index("units") < tail.plain.index("×%")


def test_r_pe_bench_50_the_2d_array_name_keeps_its_where_whole(defc):
    """FX9b F-X9-6 (X9 capture `v5b`): VAL_BLK_DEF_0001 (2-D) selection x0..1, y0..1. Inc 8's bar paints the name
    label in at most the cells its CSS gives it (``#patch_sheet_name`` max-width, read here from Inc 8's sheet), and
    `VAL_BLK_DEF_0001[x0..1,y0..1]` is one cell more: the label lost its closing `]`, so the where read as an open
    range. The where is the bar's own news (the selection), so it stays whole and the name gives way with one `…`;
    a name that fits (MAP_DEF_0001, 50/1) is untouched."""
    from s19_app.tui.screens_directionb.patch_editor.sheet import StagingSheet

    cap = int(re.search(r"#patch_sheet_name \{[^}]*max-width: (\d+)", StagingSheet.DEFAULT_CSS).group(1))
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    name, _tail = tail_of(o, view_state(o, cursor=(1, 1), anchor=(0, 0)))
    assert name.endswith("[x0..1,y0..1]"), name
    assert cell_len(name) <= cap, (name, cap)
    assert name.startswith("VAL_BLK_DEF_") and name.count("…") == 1, name


def test_r_pe_bench_50_the_tail_names_the_keys(defc):
    """R-PE-BENCH.50 - the tail ends with `enter apply  alt+s stage record` when it fits."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    _name, tail = tail_of(o, view_state(o), width=200)
    assert tail.plain.rstrip().endswith("enter apply  alt+s stage record")


def test_r_pe_bench_66_1_a_preview_without_notices_is_a_tick(defc):
    """R-PE-BENCH.66/1 - VAL_BLK_DEF_0001 +Δ 5: the preview encodes -> the tail holds ` ✓` after the cell count."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    enc = encode_values(o.d, o.a2l, {(0, 0): "41.9", (1, 0): "16.0"}, o.image)
    _name, tail = tail_of(o, view_state(o, tool="d", cursor=(1, 0), anchor=(0, 0), preview=enc, edit={(0, 0): "41.9"}))
    assert "+Δ on 2 cells ✓" in tail.plain
    assert "✗" not in tail.plain


def test_r_pe_bench_66_2_a_refused_preview_shows_its_message(defc):
    """R-PE-BENCH.66/2 - Set 60: ` ✗ VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    refusal = encode_values(o.d, o.a2l, {(0, 0): "60"}, o.image)
    _name, tail = tail_of(o, view_state(o, tool="s", preview=refusal, edit={(0, 0): "60"}), width=200)
    assert " ✗ VAL_BLK_DEF_0001[0,0]: 60 is outside the limits -50..50" in tail.plain


def test_r_pe_bench_66_3_a_percent_refusal_names_the_element(defc):
    """R-PE-BENCH.66/3 - CURVE_DEF_0001 ×% 50 on every point: ` ✗ CURVE_DEF_0001[1]: 78323 is outside the limits 0..65535`."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    start = blank_state(tool="p", cursor=(4, 0), anchor=(0, 0), values=o.values)
    edited = db.apply_tool(o.d, start, o.grid, o.values, "50")
    refusal = encode_values(o.d, o.a2l, dict(edited.edit), o.image)
    assert isinstance(refusal, Refusal)
    state = view_state(o, tool="p", cursor=(4, 0), anchor=(0, 0), preview=refusal, edit=dict(edited.edit))
    _name, tail = tail_of(o, state, width=200)
    assert " ✗ CURVE_DEF_0001[1]: 78323 is outside the limits 0..65535" in tail.plain


def test_r_pe_bench_66_a_preview_with_notices_counts_them(defc):
    """R-PE-BENCH.66 (verdict form) - an Encoded with 2 notices -> ` ▲ 2 notices`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    noisy = Encoded(o.d.address, bytes(o.d.byte_length), ("first notice", "second notice"))
    _name, tail = tail_of(o, view_state(o, preview=noisy, edit={(0, 0): "41.9"}), width=200)
    assert " ▲ 2 notices" in tail.plain


def test_r_pe_bench_66_one_notice_is_singular(defc):
    """FX9b F-X9-7 (X9 capture `v9-notice`): one notice reads ` ▲ 1 notice`, not `1 notices`."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    noisy = Encoded(o.d.address, bytes(o.d.byte_length), ("only notice",))
    _name, tail = tail_of(o, view_state(o, preview=noisy, edit={(0, 0): "41.9"}), width=200)
    assert re.search(r" ▲ 1 notice(?!s)", tail.plain), tail.plain


@pytest.mark.parametrize("width", [118, 220])
def test_r_pe_bench_93_1_2_a_long_verdict_is_cut_at_the_edge(defc, width):
    """R-PE-BENCH.93/1,2 - CURVE_DEF_0001 Set `x` × 300: a refusal verdict (294 characters; the case says 289, on
    the wording list) ends in `…` and is cut AT the bar's right edge at 118 / 220. Ruling P-056 T9 F-7: ``width`` is
    the tail's width, the name not included (I-8.5 ``bar(row, state, width)``: Inc 8's sheet passes the tail
    widget's width, as for ``formula_tail``; EX-H3: width 100 -> length 100)."""
    o = defc_obj(defc, "CURVE_DEF_0001")
    refusal = encode_values(o.d, o.a2l, {(0,): "x" * 300}, o.image)
    assert isinstance(refusal, Refusal) and len(refusal.message) > 200
    name, tail = tail_of(o, view_state(o, tool="s", preview=refusal, edit={(0,): "x" * 300}), width=width)
    assert tail.plain.endswith("…") and tail.plain.count("…") == 1
    assert cell_len(tail.plain) == width, "cut at the bar's right edge, not inside it"


def test_r_pe_bench_5_the_op_line_fits_the_bar(defc, tmp_path):
    """R-PE-BENCH.5 (the op line; unchanged at Inc 8b, the formula bar is outside the grid scroller, R-PE-DEF.95) - MAP_DEF_0001 and LARGE at 76, 114, 216: the tail is never wider than the bar."""
    o = defc_obj(defc, "MAP_DEF_0001")
    big_row, big_state = large_case(tmp_path)
    for width in (76, 114, 216):
        _n, tail = tail_of(o, view_state(o, tool="m"), width=width)
        assert cell_len(tail.plain) <= width
        _n, big_tail = dv.op_line(big_row, big_state, width)
        assert cell_len(big_tail.plain) <= width


def test_r_pe_bench_90_2_a_unit_in_the_op_line_is_not_markup(defc):
    """R-PE-BENCH.90/2 - a unit `Map[b]x` opens the tail literally, with no link."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    row = sheet_row(dataclasses.replace(o.d, unit="Map[b]x"), o.a2l, o.image)
    _name, tail = dv.op_line(row, view_state(o), 118)
    assert tail.plain.lstrip().startswith("Map[b]x")
    assert not linked(tail)


def test_r_pe_bench_91_2_a_control_character_in_a_unit_is_cleaned_in_the_op_line(defc):
    """R-PE-BENCH.91/2 - a unit with U+0085 -> U+FFFD in the tail."""
    o = defc_obj(defc, "VAL_BLK_DEF_0001")
    row = sheet_row(dataclasses.replace(o.d, unit="a\x85b"), o.a2l, o.image)
    _name, tail = dv.op_line(row, view_state(o), 118)
    assert "a" + FFFD + "b" in tail.plain and "\x85" not in tail.plain


# ==========================================================================
# M9 (relevo-10) survivor of the group B mutant run: test added RED on the mutant, GREEN on the product
# ==========================================================================


@pytest.mark.parametrize("room", [8, 9, 10, 11, 12, 20, 40])
def test_r_pe_bench_38_5_the_bytes_line_stays_last_while_the_whole_grid_fits(defc, room):
    """R-PE-BENCH.38 / .5 (M9, mutant w9e: the canvas takes one line too many) - MAP_DEF_0001 (4 x 3, no window
    line): from room 8 up the bench is the definition line, the canvas, the legend, the tool row, then the bytes
    line as its last line, in at most `room` lines."""
    o = defc_obj(defc, "MAP_DEF_0001")
    lines = detail(o, view_state(o), room=room)
    assert len(lines) <= room
    assert lines[-1].plain.strip() == NO_EDIT, (room, lines[-1].plain)


# ==========================================================================
# I9 (relevo-11) ruling F-M9-1 (P-070, DF-04 a): the window line takes a canvas row, never the bytes line
# ==========================================================================


WINDOW = re.compile(r"(rows|points) \d+\.\.")


def _windowed_cases(defc, tmp_path):
    """(label, row, state, width) of three objects whose window line shows: LARGE (grid, 16 of 65,536 rows),
    MAP_DEF_0001 at width 20 (2 of its 4 columns) and CURVE_DEF_0001 at width 13 (3 of its 5 points)."""
    large_row, large_state = large_case(tmp_path)
    cases = [("LARGE", large_row, large_state, 118)]
    for name, width in (("MAP_DEF_0001", 20), ("CURVE_DEF_0001", 13)):
        o = defc_obj(defc, name)
        cases.append((name, sheet_row(o.d, o.a2l, o.image), view_state(o), width))
    return cases


@pytest.mark.parametrize("room", [8, 12, 20, 30])
def test_r_pe_bench_38_6_the_bytes_line_stays_last_while_the_window_line_shows(defc, tmp_path, room):
    """R-PE-BENCH.38 / .37 / .5 (I9, ruling F-M9-1) - an object whose window line shows: the bench ends with the
    window line, the legend, the tool row and the bytes line, in that order, in at most `room` lines. Control:
    the window line is there (`rows a..b of n` / `points a..b of n`, cut at narrow widths), so the case is the windowed one the defect dropped."""
    for label, row, state, width in _windowed_cases(defc, tmp_path):
        lines = dv.bench_detail(row, None, width, state, room)
        text = [line.plain for line in lines]
        assert len(lines) <= room, (label, room, len(lines))
        assert any(WINDOW.match(t) for t in text), (label, room, text)
        if width >= len(NO_EDIT):
            assert text[-1].strip() == NO_EDIT, (label, room, text[-1])
        else:
            assert text[-1].startswith("no edit") and text[-1].endswith("…"), (label, room, text[-1])
        assert WINDOW.match(text[-4]), (label, room, text[-4])
        assert text[-2].lstrip().startswith("s  Set"), (label, room, text[-2])
