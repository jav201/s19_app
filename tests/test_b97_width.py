"""Batch-97 width and height derivation (HLR-149) — the Check Editor arms (Inc-3).

TC-B97-34..38 and TC-B97-59 over the Check Editor; the Patch, Builder and
Execution arms join at Inc-4..6 and the full sweep at Inc-7. Every reading
is painted (``render_strips()``, C-32): a width is read as the text the
terminal shows after the resize, never as ``get_render_width`` or
``styles.width`` (PC-8 / PC-19 — the spike showed ``refresh(layout=True)``
alone reading right while painting shifted columns).

PC-24: every vertical arm that runs at 118x54 also runs at 118x53, the body
height 118x54 keeps once the Inc-8 two-row key bar lands.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, HorizontalScroll
from textual.widgets import Button, DataTable, Static

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import DEMO_A2L, LONG_NAME, LONGEST_NAME, SIX_13A00, long_name_a2l, open_check_editor
from tests.b97_probes import (
    blank_panel_rows,
    clipped_overflow,
    displayed_descendants,
    is_displayed,
    painted_rows,
    settle,
)
from tests.test_b97_check_editor import column_span, include, need, painted_table, run

ADDRESS_RE = re.compile(r"^0x[0-9A-F]{8}$")
PRIMARY = ("check_validate_button", "check_write_button")
RANGE_SAMPLES = ((118, 54), (118, 53), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70))


# --------------------------------------------------------------------------- #
# TC-B97-34 — LLR-149.1
# --------------------------------------------------------------------------- #


def test_tc_b97_34_check_layout_monotonic_in_its_inputs() -> None:
    """TC-B97-34 (LLR-149.1, layer 0): every width ``check_layout`` derives is
    non-decreasing as the measured table / card widths grow, and strictly
    greater at the 220x60 reading (120 / 70) than at 118x54 (68 / 38).

    RED on main: no ``check_layout``. Mutation: Parameter fixed at 42.
    """
    layout = getattr(sdb, "check_layout", None)
    assert layout is not None
    samples = [(68, 38), (94, 54), (120, 70), (144, 85)]
    readings = [layout(t, c, 11) for t, c in samples]
    for field in ("param", "fmt", "fields_name", "mem_label"):
        series = [getattr(r, field) for r in readings]
        assert series == sorted(series), (field, series)
    small, large = layout(68, 38, 11), layout(120, 70, 11)
    assert large.param > small.param and large.fields_name > small.fields_name


def _reading(app, panel) -> dict:
    table = panel.query_one("#check_param_table", DataTable)
    rows = painted_rows(app, table)
    span_a = column_span(table, 2)
    span_p = column_span(table, 1)
    return {
        "msx": table.max_scroll_x,
        "header": rows[0],
        "fmt_w": table.ordered_columns[3].width,
        "addresses": [r[span_a[0]:span_a[1]] for r in rows[1:] if r.strip()],
        "params": [r[span_p[0]:span_p[1]].rstrip() for r in rows[1:] if r.strip()],
        "rows": rows,
    }


def test_tc_b97_34_painted_widths_follow_four_resizes(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, painted arm): in one session 118x54 → 160x56 →
    220x60 → 260x70 → 118x54 the ledger repaints at every step — no horizontal
    scroll, every visible address in full, the Fmt header uncropped, the
    47-cell name clipped first+``…``+tail at 118 and in full from 220 — and the
    six ``0x13A00`` Fields lines stay distinct; back at 118x54 the painted rows
    equal the first reading.

    RED on main: ``max_scroll_x`` 25 at 118x54. Mutation: ``Column.width`` +
    ``refresh(layout=True)`` alone (the PC-8 vacuous path); cell text left as
    built at load.
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        table.move_cursor(row=panel._visible_params.index(LONGEST_NAME))
        for name in SIX_13A00:
            await include(panel, pilot, name)
        table.move_cursor(row=panel._visible_params.index(LONGEST_NAME))
        table.scroll_to(y=0, animate=False)
        await settle(pilot, 3)
        out = []
        for size in ((118, 54), (160, 56), (220, 60), (260, 70), (118, 54)):
            await pilot.resize_terminal(*size)
            await settle(pilot, 6)
            table.scroll_to(y=0, animate=False)
            await settle(pilot, 3)
            reading = _reading(app, panel)
            holder = panel.query("#check_fields_lines")
            fields = [r.rstrip() for r in painted_rows(app, holder.first())[1:] if r.strip()] if holder else []
            painted_long = [
                r[column_span(table, 1)[0]:column_span(table, 1)[1]].rstrip()
                for r in reading["rows"][1:]
                if r.strip()
            ]
            index = panel._visible_params.index(LONGEST_NAME)
            out.append((size, reading, fields, painted_long[index] if index < len(painted_long) else None))
        return out

    readings = run(tmp_path, (118, 54), body)
    for size, reading, fields, longest in readings:
        assert reading["msx"] == 0, (size, reading["msx"])
        assert reading["addresses"] and all(ADDRESS_RE.match(a) for a in reading["addresses"]), (size, reading["addresses"][:3])
        label = "Fmt · Unit" if reading["fmt_w"] >= 10 else "Fmt"
        assert re.search(re.escape(label) + r"(\s|$)", reading["header"]), (size, reading["header"])
        assert len(fields) == 6 and len(set(fields)) == 6, (size, fields)
        if size[0] >= 220:
            assert longest == LONGEST_NAME, (size, longest)
        elif size[0] == 118:
            assert longest is not None and longest.startswith("ASAM…") and longest.endswith("NO_DEFAULT_VALUE"), (size, longest)
    assert readings[0][1]["rows"] == readings[-1][1]["rows"], "back at 118x54 the ledger paints as at first"


def test_tc_b97_34_resize_while_hidden_rederives_on_show(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, hidden arm): resizing to 220x60 while another
    screen is shown, then showing the Check Editor, paints the ledger as a
    direct 220x60 session does.

    RED: the mutation drops the ``on_show`` trigger (the panel keeps 118 widths).
    """

    async def hidden(app, pilot, panel):
        app.action_show_screen("workspace")
        await settle(pilot, 3)
        await pilot.resize_terminal(220, 60)
        await settle(pilot, 4)
        app.action_show_screen("check_editor")
        await settle(pilot, 6)
        reading = _reading(app, panel)
        return reading["header"], reading["params"]

    async def direct(app, pilot, panel):
        reading = _reading(app, panel)
        return reading["header"], reading["params"]

    shown = run(tmp_path / "a", (118, 54), hidden)
    assert shown == run(tmp_path / "b", (220, 60), direct)
    assert LONGEST_NAME in shown[1] and "Fmt · Unit" in shown[0], shown[0]


# --------------------------------------------------------------------------- #
# TC-B97-35 — LLR-149.2
# --------------------------------------------------------------------------- #


class _Synthetic(App):
    def __init__(self, scroll: bool) -> None:
        super().__init__()
        self._scroll = scroll

    def compose(self) -> ComposeResult:
        cards = [Static("x" * 21, classes="card") for _ in range(6)]
        holder = HorizontalScroll(*cards) if self._scroll else Horizontal(*cards)
        holder.styles.height = 3
        for card in cards:
            card.styles.width = 21
        panel = Container(holder, id="panel")
        panel.styles.width = 80
        yield panel


def test_tc_b97_35_predicate_self_check() -> None:
    """TC-B97-35 (predicate, P-52): six 21-cell cards inside a ``HorizontalScroll``
    count 0 under the clipped-region predicate; inside a non-scrolling
    ``Horizontal`` the cards past the panel count."""

    async def count(scroll: bool) -> int:
        app = _Synthetic(scroll)
        async with app.run_test(size=(100, 10)) as pilot:
            await pilot.pause()
            return len([w for w in clipped_overflow(app.query_one("#panel")) if w.has_class("card")])

    assert asyncio.run(count(True)) == 0
    assert asyncio.run(count(False)) >= 3


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_35_no_horizontal_overflow(tmp_path: Path, size) -> None:
    """TC-B97-35 (LLR-149.2): 0 displayed descendants of the Check Editor whose
    clipped region leaves the panel on x, over >= 10 descendants, on both sides
    of the 120-column breakpoint (which flips between 119 and 120).

    RED on main (P-10): 1 overflowing descendant at 118x54.
    """

    async def body(app, pilot, panel):
        narrow = app.query_one("#workspace_body").has_class("width-narrow")
        return [w.id or type(w).__name__ for w in clipped_overflow(panel)], len(displayed_descendants(panel)), narrow

    offenders, population, narrow = run(tmp_path, size, body)
    assert offenders == [], (size, offenders)
    assert population >= 10
    assert narrow is (size[0] < 120)


# --------------------------------------------------------------------------- #
# TC-B97-36 — LLR-149.3
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", RANGE_SAMPLES)
def test_tc_b97_36_validate_and_write_inside_at_scroll_zero(tmp_path: Path, size) -> None:
    """TC-B97-36 (LLR-149.3, Check arm): Validate and Write lie inside the panel
    region with the panel at its top, over the range and at 118x53 (PC-24).

    Pin on main (the editors' actions are inside, P-11); RED by mutation: the
    columns given a fixed height past the panel.
    """

    async def body(app, pilot, panel):
        panel.scroll_home(animate=False)
        await settle(pilot, 2)
        return {i: panel.query_one(f"#{i}").region for i in PRIMARY}, panel.region

    regions, panel_region = run(tmp_path, size, body)
    for wid, region in regions.items():
        assert panel_region.contains_region(region), (size, wid, region, panel_region)


# --------------------------------------------------------------------------- #
# TC-B97-37 — LLR-149.4
# --------------------------------------------------------------------------- #

CATEGORIES = ("nowrap-ledger", "nowrap-heading", "nowrap-fields", "nowrap-legend")


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_37_no_wrapped_row_and_tail_kept_clips(tmp_path: Path, size) -> None:
    """TC-B97-37 (LLR-149.4, Check arm): every member of the panel's no-wrap set
    (read from the DOM by category class) paints one terminal row per logical
    line; every Parameter cell wider than its column paints its LLR-145.3 clip
    with exactly one ``…``; the 75 painted ledger rows are pairwise distinct;
    the ``Fmt · Unit`` cell keeps the width and clips the unit.

    Code-reviewer F2 (Inc-3 gate): run at all six LLR-149.2 sizes, both sides
    of the 120-column breakpoint, over the long-name A2L — its 173-cell name is
    wider than the Parameter column at every size (guard), so the clip clause
    is exercised at 220 and 260 too, not only where demo names happen to clip.

    RED on main: no member carries a no-wrap category class (the guard).
    """

    async def body(app, pilot, panel):
        for name in SIX_13A00:
            await include(panel, pilot, name)
        members = {cat: [w for w in panel.query(f".{cat}") if is_displayed(w)] for cat in CATEGORIES}
        wraps = []
        for cat, widgets in members.items():
            for w in widgets:
                if isinstance(w, DataTable):
                    continue
                lines = str(w.render()).split("\n")
                height = w.get_content_height(w.content_region.size, app.size, w.content_region.width)
                if height != len(lines) or w.region.height < len(lines):
                    wraps.append((w.id, height, len(lines), w.region.height))
        table = panel.query_one("#check_param_table", DataTable)
        width = table.ordered_columns[1].width
        fmt_w = table.ordered_columns[3].width
        span_p, span_f = column_span(table, 1), column_span(table, 3)
        painted = await painted_table(app, pilot, table)
        names = list(panel._visible_params)
        units = [panel._param_rows[n][2] for n in names]
        return {c: len(m) for c, m in members.items()}, wraps, width, fmt_w, span_p, span_f, painted, names, units

    counts, wraps, width, fmt_w, span_p, span_f, painted, names, units = run(
        tmp_path, size, body, a2l=long_name_a2l(tmp_path)
    )
    assert LONG_NAME in names and len(LONG_NAME) > width, "guard: the long name clips at this size"
    assert all(n >= 1 for n in counts.values()), counts
    assert wraps == [], wraps
    def clip(name: str, width: int) -> str:
        # The LLR-145.3 clip restated here, never imported from the code under
        # test (an oracle sharing the implementation cannot see its mutant).
        first = name.split(".")[0]
        if len(first) + 2 > width:
            first = first[: max(1, width // 3)]
        return first + "…" + name[len(name) - (width - len(first) - 1):]

    bad = []
    for i, name in enumerate(names):
        text = painted[i][span_p[0]:span_p[1]].rstrip()
        if len(name) > width and (text != clip(name, width) or text.count("…") != 1):
            bad.append((name, text))
        unit = painted[i][span_f[0]:span_f[1]].rstrip()
        source = units[i].rstrip()
        token = source.split(" ")[0]
        if len(source) > fmt_w and len(token) >= fmt_w:
            # Inside the 120..133 band the column is 4 cells: `u128` fills it,
            # so the width is painted alone and the unit is dropped with no
            # room for a `…` (LLR-149.4: the unit is clipped before the width;
            # the full-name line shows the whole text, ux-reviewer L2).
            if unit != token[:fmt_w]:
                bad.append((source, unit))
        elif len(source) > fmt_w:
            if not (unit.endswith("…") and unit.startswith(token)):
                bad.append((source, unit))
        elif unit != source:
            bad.append((source, unit))
    assert bad == [], bad[:5]
    assert len({painted[i] for i in range(len(names))}) == len(names)


@pytest.mark.parametrize("size", [(118, 54), (220, 60)])
def test_tc_b97_37_status_line_stays_one_row_with_a_long_typed_address(tmp_path: Path, size) -> None:
    """TC-B97-37 (LLR-149.4, the status line; code-reviewer F5): a refused
    memory row echoes the typed address in ``#check_status``; a 90-character
    entry still paints ONE row ending in the CSS ``…`` — the one no-wrap member
    whose text Python does not pre-clip, so the CSS rule is load-bearing here.

    RED by mutation M24 (``text-wrap: wrap`` on the no-wrap selector list):
    the row paints the text's first segment with no ``…``.
    """

    async def body(app, pilot, panel):
        panel.query_one("#check_mem_address_input").value = "not-an-address-" * 6
        panel.query_one("#check_mem_add_button").press()
        await settle(pilot, 2)
        status = panel.query_one("#check_status")
        rows = painted_rows(app, status)
        text = str(status.render())
        height = status.get_content_height(status.content_region.size, app.size, status.content_region.width)
        return rows, text, height

    rows, text, height = run(tmp_path, size, body)
    assert "bad memory address" in text and len(text) > 100, text
    assert len(rows) == 1 and height == 1, (rows, height)
    assert rows[0].rstrip().endswith("…"), rows[0]


# --------------------------------------------------------------------------- #
# TC-B97-38 — LLR-149.5
# --------------------------------------------------------------------------- #


def _header_void(app, table) -> tuple:
    header = painted_rows(app, table)[0]
    content = table.content_region
    extent = len(header.rstrip()) - 1
    void = (content.x + content.width - table.region.x) - (extent + 1)
    return void, header


@pytest.mark.parametrize("size", [(160, 56), (220, 60), (260, 70)])
def test_tc_b97_38_ledger_takes_the_width_its_split_assigns(tmp_path: Path, size) -> None:
    """TC-B97-38 (LLR-149.5, width clause): the ledger's header row leaves at most
    2 void cells after its painted extent, or more only when no cell in the
    band is clipped; the 47-cell name paints in full at 220x60; the Parameter
    column and the Fields name field are wider at 220x60 than at 118x54.

    Pin on main for the void (the shipped table fills its region); RED by
    mutation: the Parameter column fixed at 30 cells (void > 2 beside clipped
    cells).
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        void, header = _header_void(app, table)
        painted = await painted_table(app, pilot, table)
        clipped = [line for line in painted.values() if "…" in line]
        layout = getattr(panel, "_layout", None)
        return void, header, len(clipped), table.ordered_columns[1].width, layout

    void, header, clipped, width, layout = run(tmp_path, size, body)
    assert void <= 2 or clipped == 0, (size, void, clipped, header)
    if size == (220, 60):
        assert width >= len(LONGEST_NAME)
    assert layout is not None
    small = sdb.check_layout(68, 38, 11)
    if size[0] >= 220:
        assert layout.param > small.param and layout.fields_name > small.fields_name, layout


@pytest.mark.parametrize("size", [(118, 54), (118, 53), (220, 60)])
def test_tc_b97_38_no_blank_row_outside_the_ledger(tmp_path: Path, size) -> None:
    """TC-B97-38 (LLR-149.5, height clause; PC-24 at 118x53): no panel row is
    painted blank across the panel outside the ledger's band.

    Regression pin (main: Check 0 blank rows, P-32); RED by mutation: a
    ``margin-top: 1`` on the spec row.
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table")
        return blank_panel_rows(app, panel, outside=table)

    assert run(tmp_path, size, body) == []


# --------------------------------------------------------------------------- #
# TC-B97-59 — LLR-149.6
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(80, 24), (100, 40), (220, 40)])
def test_tc_b97_59_below_the_range_actions_reachable(tmp_path: Path, size) -> None:
    """TC-B97-59 (LLR-149.6, Check arm): below the range, ``tab`` from the panel
    top reaches Validate and Write (<= 200 presses) and each lies inside the
    panel once focused; ``pagedown`` from scroll 0 brings each inside (<= 20);
    no two displayed buttons overlap.

    Pin on main; RED by mutation: ``overflow: hidden`` on the panel.
    """

    async def body(app, pilot, panel):
        out = {}
        for wid in PRIMARY:
            panel.scroll_home(animate=False)
            panel.query_one("#check_param_filter").focus()
            await settle(pilot, 2)
            presses = 0
            while (app.focused is None or app.focused.id != wid) and presses < 200:
                await pilot.press("tab")
                presses += 1
            await settle(pilot, 3)
            inside_tab = panel.region.contains_region(panel.query_one(f"#{wid}").region)
            panel.scroll_home(animate=False)
            panel.focus()
            await settle(pilot, 2)
            pages = 0
            while not panel.region.contains_region(panel.query_one(f"#{wid}").region) and pages < 20:
                await pilot.press("pagedown")
                await settle(pilot, 1)
                pages += 1
            inside_page = panel.region.contains_region(panel.query_one(f"#{wid}").region)
            out[wid] = (presses, inside_tab, pages, inside_page)
        buttons = [b.region for b in panel.query(Button) if is_displayed(b) and b.region.width]
        overlaps = [
            (a, b) for i, a in enumerate(buttons) for b in buttons[:i] if a.overlaps(b)
        ]
        return out, overlaps

    out, overlaps = run(tmp_path, size, body)
    for wid, (presses, inside_tab, pages, inside_page) in out.items():
        assert presses < 200 and inside_tab, (size, wid, presses)
        assert pages < 20 and inside_page, (size, wid, pages)
    assert overlaps == [], overlaps
