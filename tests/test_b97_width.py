"""Batch-97 width and height derivation (HLR-149) — the Check Editor (Inc-3), Patch Editor (Inc-4) and Flow Builder (Inc-5) arms.

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


# =========================================================================== #
# Inc-4 — the Patch Editor arms of TC-B97-34..38 and TC-B97-59
# =========================================================================== #

from tests.b97_fixtures import (  # noqa: E402
    CALIB_ENTRIES,
    _bytes_entry,
    calib_hotfix,
    load_change_file,
    open_patch_editor,
    write_changeset,
)

PATCH_PRIMARY = (
    "patch_doc_load_button",
    "patch_doc_save_button",
    "patch_doc_validate_button",
    "patch_doc_apply_button",
)
PATCH_CATEGORIES = ("nowrap-ledger", "nowrap-heading", "nowrap-ribbon", "nowrap-legend")
#: A change-file name far wider than the ribbon at any size of the range; the
#: ribbon must keep its tail (LLR-149.4, file names).
LONG_FILE = "calib_" + "_".join(f"segment{i:02d}" for i in range(11)) + "_TAIL_MARK.json"


def run_patch(tmp_path: Path, size, body, *, path=None):
    """Open the Patch Editor at ``size`` with ``prg.s19`` and a change-set loaded."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await open_patch_editor(app, pilot)
            await load_change_file(app, pilot, panel, path or calib_hotfix(tmp_path))
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


def test_tc_b97_34_patch_layout_monotonic_in_its_inputs() -> None:
    """TC-B97-34 (LLR-149.1, Patch arm, layer 0): every width ``patch_layout``
    derives is non-decreasing as the measured ledger / inspector widths grow,
    and the Value column and the strip's bytes per row are strictly greater at
    the 220x60 reading (115 / 75) than at 118x54 (65 / 41) — 8 then 16 bytes.

    RED on main: no ``patch_layout``. Mutation: the strip fixed at 8 bytes.
    """
    layout = getattr(sdb, "patch_layout", None)
    assert layout is not None
    samples = [(65, 41), (90, 57), (115, 75), (140, 92)]
    readings = [layout(ledger, inspector, 6) for ledger, inspector in samples]
    for field in ("value", "strip_bytes", "status", "address"):
        series = [getattr(r, field) for r in readings]
        assert series == sorted(series), (field, series)
    small, large = layout(65, 41, 6), layout(115, 75, 6)
    assert small.strip_bytes == 8 and large.strip_bytes == 16
    assert large.value > small.value


def _patch_reading(app, panel) -> dict:
    from tests.test_b97_patch_editor import strip_reading

    table = panel.query_one("#patch_doc_entries_table", DataTable)
    rows = painted_rows(app, table)
    span = column_span(table, 2)
    return {
        "msx": table.max_scroll_x,
        "values": [r[span[0]:span[1]].rstrip() for r in rows[1:] if r.strip()],
        "strip": [len(r["offsets"]) for r in strip_reading(app, panel)],
        "rows": rows,
    }


def test_tc_b97_34_patch_painted_widths_follow_four_resizes(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, Patch painted arm, PC-19): in one session 118x54,
    160x56, 220x60, 260x70 and back to 118x54 the ledger and the strip repaint
    at every step — no horizontal scroll, the 8-byte ``A5`` run clipped with
    one ``…`` at 118 and whole from 220, the strip 8 bytes per row at 118 and
    16 from 220 — and back at 118x54 the painted ledger equals the first
    reading.

    RED: the strip not re-rendered on resize (M15); ``Column.width`` +
    ``refresh(layout=True)`` alone (the PC-8 vacuous path, M22).
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#patch_doc_entries_table", DataTable)
        table.move_cursor(row=3)
        await settle(pilot, 3)
        out = []
        for size in ((118, 54), (160, 56), (220, 60), (260, 70), (118, 54)):
            await pilot.resize_terminal(*size)
            await settle(pilot, 6)
            out.append((size, _patch_reading(app, panel)))
        return out

    readings = run_patch(tmp_path, (118, 54), body)
    run_a5 = " ".join(["A5"] * 8)
    for size, reading in readings:
        assert reading["msx"] == 0, (size, reading["msx"])
        assert len(reading["values"]) >= 4, (size, reading["values"])
        value = reading["values"][3]
        if size[0] >= 220:
            assert value == run_a5 and reading["strip"] == [16], (size, value, reading["strip"])
        if size[0] == 118:
            assert value.count("…") == 1 and run_a5.startswith(value[:-1]), (size, value)
            assert reading["strip"] == [8], (size, reading["strip"])
    assert readings[0][1]["rows"] == readings[-1][1]["rows"]


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_35_patch_no_horizontal_overflow(tmp_path: Path, size) -> None:
    """TC-B97-35 (LLR-149.2, Patch arm): 0 displayed descendants of the Patch
    Editor whose clipped region leaves the panel on x, over >= 10, on each of
    the three tabs and both sides of the 120-column breakpoint.

    RED on main (P-10): 1 overflowing descendant at 118x54.
    """

    async def body(app, pilot, panel):
        found = []
        for chip in ("patch_tab_inspector", "patch_tab_json", "patch_tab_checks"):
            if panel.query(f"#{chip}"):
                panel.query_one(f"#{chip}").press()
                await settle(pilot, 3)
            found += [w.id or type(w).__name__ for w in clipped_overflow(panel)]
        return found, len(displayed_descendants(panel))

    offenders, population = run_patch(tmp_path, size, body)
    assert offenders == [], (size, offenders)
    assert population >= 10


@pytest.mark.parametrize("size", RANGE_SAMPLES)
def test_tc_b97_36_patch_document_actions_inside_at_scroll_zero(tmp_path: Path, size) -> None:
    """TC-B97-36 (LLR-149.3, Patch arm; PC-24 at 118x53): Load, Save, Validate
    and Apply lie inside the panel region with the panel at its top.

    RED by mutation: the ledger given a fixed height past the panel (M23).
    """

    async def body(app, pilot, panel):
        panel.scroll_home(animate=False)
        await settle(pilot, 2)
        return {i: panel.query_one(f"#{i}").region for i in PATCH_PRIMARY}, panel.region

    regions, panel_region = run_patch(tmp_path, size, body)
    for wid, region in regions.items():
        assert panel_region.contains_region(region), (size, wid, region, panel_region)


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_37_patch_no_wrapped_row_and_clips(tmp_path: Path, size) -> None:
    """TC-B97-37 (LLR-149.4, Patch arm): every member of the no-wrap set (by
    category class: the ledger, the inspector headings, the ribbon, the legend)
    paints one row per logical line; a Value cell wider than its column keeps
    its head with exactly one ``…``; the ribbon keeps the tail of a file name
    wider than itself; the 6 painted ledger rows are pairwise distinct.

    RED on main: no member carries a no-wrap category class (the guard); the
    ribbon clipped head-first (M24).
    """
    path = write_changeset(tmp_path / LONG_FILE, [_bytes_entry(a, r) for a, r in CALIB_ENTRIES])

    async def body(app, pilot, panel):
        if panel.query("#patch_tab_json"):
            panel.query_one("#patch_tab_json").press()  # the inspector headings live there
        await settle(pilot, 4)
        members = {c: [w for w in panel.query(f".{c}") if is_displayed(w)] for c in PATCH_CATEGORIES}
        wrapped = []
        for category, widgets in members.items():
            for w in widgets:
                if isinstance(w, Static):
                    lines = str(w.render()).count("\n") + 1
                    height = w.get_content_height(w.size, app.size, w.content_region.width)
                    if height != lines:
                        wrapped.append((category, w.id, height, lines))
        reading = _patch_reading(app, panel)
        holder = panel.query_one("#patch_identity_ribbon")
        ribbon = painted_rows(app, holder)[0].rstrip()
        return {c: len(ws) for c, ws in members.items()}, wrapped, reading, (ribbon, holder.content_region.width)

    members, wrapped, reading, ribbon = run_patch(tmp_path, size, body, path=path)
    assert all(n >= 1 for n in members.values()), members
    assert wrapped == [], wrapped
    for value in reading["values"]:
        if "…" in value:
            assert value.count("…") == 1 and value.endswith("…"), value
    assert len(set(reading["rows"][1:7])) == 6
    ribbon, ribbon_w = ribbon
    assert ribbon.endswith("_TAIL_MARK.json · change"), ribbon
    # The name is clipped exactly where it does not fit (it fits from 220 on;
    # Windows' path limit caps how long a fixture name can be).
    assert ("…" in ribbon) is (len(LONG_FILE) + len(" · change") > ribbon_w), (ribbon, ribbon_w)


@pytest.mark.parametrize("size", [(160, 56), (220, 60), (260, 70)])
def test_tc_b97_38_patch_ledger_takes_its_width(tmp_path: Path, size) -> None:
    """TC-B97-38 (LLR-149.5, Patch width clause): the ledger's header row leaves
    at most 2 void cells after its painted extent, and the Value column is
    wider at these sizes than at 118x54.

    RED by mutation: the Value column fixed at 22 cells (M25).
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#patch_doc_entries_table", DataTable)
        void, header = _header_void(app, table)
        return void, header, table.ordered_columns[2].width

    void, header, width = run_patch(tmp_path, size, body)
    assert void <= 2, (size, void, header)
    assert width > sdb.patch_layout(65, 41, 6).value


@pytest.mark.parametrize("size", [(118, 54), (118, 53), (220, 60)])
def test_tc_b97_38_patch_no_blank_row_outside_ledger_and_card(tmp_path: Path, size) -> None:
    """TC-B97-38 (LLR-149.5, Patch height clause; PC-24 at 118x53): no panel row
    is painted blank across the panel outside the ledger and the inspector.

    RED on main (P-32): 3 / 2 blank rows outside the ledger.
    """

    async def body(app, pilot, panel):
        main = panel.query("#patch_main")
        return blank_panel_rows(app, panel, outside=main.first() if main else None)

    assert run_patch(tmp_path, size, body) == []


@pytest.mark.parametrize("size", [(80, 24), (100, 40), (220, 40)])
def test_tc_b97_59_patch_below_the_range_actions_reachable(tmp_path: Path, size) -> None:
    """TC-B97-59 (LLR-149.6, Patch arm): below the range ``tab`` from the panel
    top reaches each document action (<= 200 presses) and it lies inside the
    panel once focused; ``pagedown`` from scroll 0 brings each inside (<= 20);
    no two displayed buttons overlap.

    RED by mutation: ``overflow: hidden`` on the panel (M26).
    """

    async def body(app, pilot, panel):
        out = {}
        for wid in PATCH_PRIMARY:
            panel.scroll_home(animate=False)
            panel.query_one("#patch_doc_entries_table").focus()
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
        overlaps = [(a, b) for i, a in enumerate(buttons) for b in buttons[:i] if a.overlaps(b)]
        return out, overlaps

    out, overlaps = run_patch(tmp_path, size, body)
    for wid, (presses, inside_tab, pages, inside_page) in out.items():
        assert presses < 200 and inside_tab, (size, wid, presses)
        assert pages < 20 and inside_page, (size, wid, pages)
    assert overlaps == [], overlaps



# =========================================================================== #
# Inc-5 — the Flow Builder arms of TC-B97-34..38 and TC-B97-59
# =========================================================================== #

from textual.widgets import Input  # noqa: E402

from s19_app.tui import flow_screens as fs  # noqa: E402
from tests.b97_fixtures import patch_chain_demo  # noqa: E402
from tests.b97_fixtures import flow_project, load_flow, open_flow_builder  # noqa: E402

FLOW_CATEGORIES = ("nowrap-pipeline", "nowrap-ribbon", "nowrap-legend")


async def _poll(pilot, predicate, attempts: int = 60) -> bool:
    for _ in range(attempts):
        await pilot.pause()
        if predicate():
            return True
    return False


def _laid_out(panel) -> bool:
    """The Builder's layout pass ran for the size now shown (D21 inputs)."""
    scroll = panel.query("#flow_pipeline_scroll")
    if not scroll:
        return True
    return getattr(panel, "_layout_key", None) is not None and panel._layout_key[0] == scroll.first().scrollable_content_region.width


#: A 60-cell change-doc ref (the widest real values, A.5): wider than a card
#: at every size of the range, so a card band always holds a clipped line.
WIDE_REF = "calibration_hotfix_release_candidate_" + "w" * 13 + "_TAIL.json"
assert len(WIDE_REF) == 60


def run_flow_builder(tmp_path: Path, size, body, *, ext: bool = True, wide: bool = False):
    """Open the Flow Builder at ``size`` with ``patch_chain`` loaded — its
    change doc a 60-cell ref when ``wide`` — (and the EXT-STEP form open when
    ``ext``) and return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = flow_project(app)
            stem = "patch_chain"
            if wide:
                from tests.b97_fixtures import patch_chain_demo, write_flow

                blocks = patch_chain_demo()
                blocks[1] = type(blocks[1])(WIDE_REF)
                stem = "wide_chain"
                write_flow(project_dir, stem, blocks)
            panel = await open_flow_builder(app, pilot)
            await load_flow(app, pilot, stem)
            if ext:
                panel.query_one("#flow_palette_external_step").press()
                await _poll(pilot, lambda: is_displayed(panel.query_one("#flow_ext_log")))
            await _poll(pilot, lambda: _laid_out(panel))
            await settle(pilot, 2)
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


def _card_width(app, panel):
    """The painted width of the first card, or ``None`` with no pipeline."""
    holder = panel.query("#flow_pipeline")
    if not holder:
        return None
    top = next(r for r in painted_rows(app, holder.first()) if "╭" in r)
    return top.index("╮") - top.index("╭") + 1


def test_tc_b97_34_pipeline_layout_monotonic_in_its_inputs() -> None:
    """TC-B97-34 (LLR-149.1, Builder arm, layer 0): ``pipeline_layout``'s card
    width is non-decreasing as the rail's measured width grows, never below
    the 21-cell minimum, strictly greater at the 220x60 reading (192 cells)
    than at 118x54 (108) for the 4-block demo, and four cards at 108 fill the
    rail (4·24 + 3·4 = 108).

    RED: no ``pipeline_layout`` on main (fixed 24-cell blocks on an 88-cell
    canvas). Mutation: the card width fixed at 24.
    """
    layout = getattr(fs, "pipeline_layout", None)
    assert layout is not None
    widths = [layout(w, 4).card_w for w in (60, 108, 140, 192, 252)]
    assert widths == sorted(widths) and min(widths) >= 21, widths
    assert layout(192, 4).card_w > layout(108, 4).card_w
    assert layout(108, 4).card_w == 24 and 4 * 24 + 3 * fs.CABLE_W == 108
    assert layout(108, 5).card_w == 21  # the rail scrolls from the 5th card at 118


@pytest.mark.parametrize("n_cards", [2, 3, 4, 5, 6])
def test_tc_b97_38_pipeline_spare_cells_go_to_the_cables(n_cards) -> None:
    """TC-B97-38 (LLR-149.5, Builder width clause, layer 0; gate fold F2):
    whenever the cards are wider than the 21-cell minimum, the painted chain
    is exactly as wide as the rail — ``card_w·n + CABLE_W·(n−1) + spare``
    with ``0 ≤ spare ≤ n − 1`` cells, one more cell on each of the first
    ``spare`` cables — so no void is left right of the last card at any
    width, the off-grid ones included.

    RED on the pre-fold tree: ``PipelineLayout`` has no ``spare`` (integer
    division left up to n − 1 void cells). Mutation: the spare cells dropped.
    """
    blocks = list(patch_chain_demo()) + list(patch_chain_demo())
    blocks = blocks[:n_cards]
    for avail in range(60, 261):
        layout = fs.pipeline_layout(avail, n_cards)
        # Skip only where the minimum binds (the rail scrolls); a chain at
        # exactly 21 cells with spare cells still owes the full width.
        if (avail - fs.CABLE_W * (n_cards - 1)) // n_cards < fs.CARD_MIN_W:
            continue
        assert 0 <= layout.spare <= n_cards - 1, (avail, layout)
        lines = fs.pipeline_text(blocks, layout.card_w, layout.spare).plain.split("\n")
        assert {len(line) for line in lines} == {avail}, (avail, n_cards, layout, {len(line) for line in lines})


def test_tc_b97_34_builder_painted_widths_follow_four_resizes(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, Builder painted arm): in one session 118x54 →
    160x56 → 220x60 → 260x70 → 118x54, the painted card width and the
    EXT-STEP command input's width are non-decreasing, strictly greater at 220
    than at 118, and back at 118x54 the painted pipeline equals the first
    reading.

    RED on main (P-22): ``#flow_ext_instruction`` 28 cells at both sizes.
    Mutation: the resize trigger removed (cards keep their 118 width).
    """

    async def body(app, pilot, panel):
        out = []
        for size in ((118, 54), (160, 56), (220, 60), (260, 70), (118, 54)):
            await pilot.resize_terminal(*size)
            await _poll(pilot, lambda: app.size == size and _laid_out(panel))
            await settle(pilot, 2)
            instruction = panel.query_one("#flow_ext_instruction").region.width
            pipeline = panel.query("#flow_pipeline")
            out.append((size, instruction, _card_width(app, panel), painted_rows(app, pipeline.first()) if pipeline else None))
        return out

    readings = run_flow_builder(tmp_path, (118, 54), body)
    instructions = [r[1] for r in readings[:4]]
    cards = [r[2] for r in readings[:4]]
    assert instructions == sorted(instructions) and instructions[2] > instructions[0], instructions
    assert None not in cards, "no pipeline"
    assert cards == sorted(cards) and cards[2] > cards[0], cards
    assert readings[0][3] == readings[-1][3], "back at 118x54 the pipeline paints as at first"


def test_tc_b97_34_builder_resize_while_hidden_rederives_on_show(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, Builder hidden arm): resizing to 220x60 while the
    workspace is shown, then showing the Flow Builder, paints the card width
    ``pipeline_layout`` derives from the rail's measured width — wider than
    the 21-cell minimum — and the same width as a session that starts at
    220x60.

    The path-independent clause (gate fold, code-reviewer F1): with both the
    ``on_resize`` and ``on_show`` triggers removed no layout pass ever runs,
    both sessions paint the 21-cell default and the equality alone stays
    GREEN; the derived-width clause goes RED. ``on_show`` alone removed is an
    equivalent mutant on this app's show path (M29: showing a ``display:
    none`` screen delivers a Resize to the panel).
    """

    async def body(app, pilot, panel):
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        await pilot.resize_terminal(220, 60)
        await _poll(pilot, lambda: app.size == (220, 60))
        app.action_show_screen("flow")
        await _poll(pilot, lambda: _laid_out(panel))
        await settle(pilot, 2)
        return _card_width(app, panel), panel.query_one("#flow_pipeline_scroll").scrollable_content_region.width

    async def direct(app, pilot, panel):
        return _card_width(app, panel)

    hidden, rail_w = run_flow_builder(tmp_path / "a", (118, 54), body, ext=False)
    assert hidden is not None, "no pipeline"
    assert hidden == fs.pipeline_layout(rail_w, 4).card_w and hidden > fs.CARD_MIN_W, (hidden, rail_w)
    assert hidden == run_flow_builder(tmp_path / "b", (220, 60), direct, ext=False)


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_35_builder_no_horizontal_overflow(tmp_path: Path, size) -> None:
    """TC-B97-35 (LLR-149.2, Builder arm): with ``patch_chain`` and the
    EXT-STEP form open, 0 displayed descendants of ``#flow_panel`` leave it on
    x (clipped-region predicate, P-52), over >= 10 descendants, on both sides
    of the 120-column breakpoint.

    RED on main (P-10): 2 overflowing descendants at 118x54.
    """

    async def body(app, pilot, panel):
        return [w.id or type(w).__name__ for w in clipped_overflow(panel)], len(displayed_descendants(panel))

    offenders, population = run_flow_builder(tmp_path, size, body)
    assert offenders == [], (size, offenders)
    assert population >= 10


@pytest.mark.parametrize("size", RANGE_SAMPLES)
def test_tc_b97_36_builder_run_inside_at_scroll_zero(tmp_path: Path, size) -> None:
    """TC-B97-36 (LLR-149.3, Builder arm; PC-24 at 118x53): with
    ``patch_chain`` and the EXT-STEP form open, ``#flow_run`` lies inside the
    panel region with the panel at its top.

    RED on main (P-11): ``#flow_run (51, 48, 16, 3)`` past the panel bottom 44.
    """

    async def body(app, pilot, panel):
        panel.scroll_home(animate=False)
        await _poll(pilot, lambda: panel.scroll_y == 0)
        return panel.query_one("#flow_run").region, panel.region

    region, panel_region = run_flow_builder(tmp_path, size, body)
    assert panel_region.contains_region(region), (size, region, panel_region)


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_37_builder_no_wrapped_row_and_tail_kept_ribbon(tmp_path: Path, size) -> None:
    """TC-B97-37 (LLR-149.4, Builder arm): every member of the Builder's
    no-wrap set (pipeline, ribbon, legend — read from the DOM by category)
    paints one terminal row per logical line, and the ribbon keeps the session
    path's tail: its painted line ends with the project folder's name.

    RED on main: no member carries a no-wrap category class (the guard).
    """

    async def body(app, pilot, panel):
        members = {cat: [w for w in panel.query(f".{cat}") if is_displayed(w)] for cat in FLOW_CATEGORIES}
        wraps = []
        for widgets in members.values():
            for w in widgets:
                lines = str(w.render()).split("\n")
                height = w.get_content_height(w.content_region.size, app.size, w.content_region.width)
                if height != len(lines) or w.region.height < len(lines):
                    wraps.append((w.id, height, len(lines), w.region.height))
        ribbon = [r.rstrip() for r in painted_rows(app, panel.query_one("#flow_name_strip")) if r.strip()]
        return {c: len(m) for c, m in members.items()}, wraps, ribbon, app.active_project_dir().name

    counts, wraps, ribbon, project = run_flow_builder(tmp_path, size, body)
    assert all(n >= 1 for n in counts.values()), counts
    assert wraps == [], wraps
    assert len(ribbon) == 1 and ribbon[0].endswith(project), ribbon


@pytest.mark.parametrize("size", [(160, 56), (163, 56), (220, 60), (223, 60), (260, 70)])
def test_tc_b97_38_builder_cards_and_ext_inputs_take_their_width(tmp_path: Path, size) -> None:
    """TC-B97-38 (LLR-149.5, Builder width clause): with a 60-cell change-doc
    ref (clipped at every size, the guard) the pipeline leaves at most 2 void
    cells after its painted extent inside the rail's content region; every
    card is at least 21 cells; each EXT-STEP input row ends within 2 cells of
    its row.

    163x56 and 223x60 are off-grid widths (gate fold, code-reviewer F2): the
    rail's width minus the cables is not a multiple of 4 there, so integer
    card widths alone left 3 void cells; the spare cells now widen the first
    cables. RED on the pre-fold tree at both sizes (void 3).

    RED by mutation: cards fixed at 24 cells (the void beside the clipped ref
    line at 220x60, the NC — M27; the first battery ran this arm on the short
    demo refs and the mutant survived, so the arm now carries the wide ref).
    """

    async def body(app, pilot, panel):
        row_voids = []
        for row_id in ("flow_ext_instruction", "flow_ext_output"):
            widget = panel.query_one(f"#{row_id}")
            row = widget.parent
            row_voids.append(row.content_region.right - widget.region.right)
        assert all(v <= 2 for v in row_voids), row_voids
        scroll = panel.query_one("#flow_pipeline_scroll")
        content = scroll.scrollable_content_region
        rows = painted_rows(app, panel.query_one("#flow_pipeline"))
        extent = max(len(r.rstrip()) for r in rows)
        void = content.width - extent
        clipped = sum(r.count("…") for r in rows)
        return void, clipped, _card_width(app, panel), row_voids

    void, clipped, card_w, row_voids = run_flow_builder(tmp_path, size, body, wide=True)
    assert clipped >= 1, "guard: the 60-cell ref clips in its card"
    assert void <= 2 or clipped == 0, (size, void, clipped)
    assert card_w >= 21
    assert all(v <= 2 for v in row_voids), row_voids


#: The Builder's named separator rows (gate fold, operator decision 2,
#: fb_A's air): one blank row above each of these, outside the growing region.
BUILDER_SEPARATED = ("#flow_palette", "#flow_clip_row", "#flow_run_row")


@pytest.mark.parametrize("size", [(118, 54), (118, 53), (220, 60)])
@pytest.mark.parametrize("phase", ["before_run", "after_run"])
def test_tc_b97_38_builder_height_goes_to_the_result(tmp_path: Path, size, phase) -> None:
    """TC-B97-38 (LLR-149.5, Builder height clause, decision B / LED-…97.11;
    PC-24 at 118x53): outside ``#flow_result`` the only blank panel rows are
    the k = 3 named separator rows, one directly above ``#flow_palette``,
    ``#flow_clip_row`` and ``#flow_run_row`` (gate fold, operator decision 2);
    the pipeline frame is exactly as tall as its cards plus the border (plus
    the horizontal scrollbar row when it scrolls), so no blank row lies inside
    it; ``#flow_result`` opens with its painted rule row, ends on the legend's
    row, paints one empty-state line before a run and, after the run of the
    4-block chain, every verdict from the ``NOTICES`` banner to the one-row
    ``wrote …`` line without scrolling, at 118x53 too.

    RED by mutation: ``#flow_pipeline_scroll { height: 1fr }`` (the A
    placement) — blank rows inside the frame; a separator margin removed —
    the named rows differ. RED on the pre-fold tree: no separator rows, no
    rule row, the ``ISSUES`` banner.
    """

    async def body(app, pilot, panel):
        if phase == "after_run":
            panel.query_one("#flow_run").press()
            await _poll(pilot, lambda: bool(panel.query("#flow_result .flow-banner")))
            await settle(pilot, 2)
        result = panel.query_one("#flow_result")
        blank = blank_panel_rows(app, panel, outside=result)
        separators = sorted(panel.query_one(wid).region.y - 1 for wid in BUILDER_SEPARATED)
        scroll = panel.query_one("#flow_pipeline_scroll")
        pipeline = panel.query_one("#flow_pipeline")
        legend = panel.query_one("#flow_legend")
        inner_blank = [r for r in painted_rows(app, scroll, scroll.scrollable_content_region) if not r.strip()]
        expected = pipeline.region.height + 2 + (1 if scroll.max_scroll_x > 0 else 0)
        rule = painted_rows(app, result)[0].strip()
        result_lines = [r.strip() for r in painted_rows(app, result, result.content_region) if r.strip()]
        wrote = [painted_rows(app, w) for w in panel.query("#flow_result .flow-wrote")]
        return (
            result_lines,
            blank,
            separators,
            scroll.region.height,
            expected,
            inner_blank,
            rule,
            result.region.bottom,
            legend.region.y,
            result.max_scroll_y,
            wrote,
        )

    (result_lines, blank, separators, frame_h, expected_h, inner_blank, rule,
     result_bottom, legend_y, max_scroll, wrote) = run_flow_builder(tmp_path, size, body, ext=False)
    assert blank == separators and len(blank) == len(BUILDER_SEPARATED), (size, phase, blank, separators)
    assert frame_h == expected_h and inner_blank == [], (frame_h, expected_h, inner_blank)
    assert rule and set(rule) == {"─"}, f"the result area opens with its rule row: {rule!r}"
    assert result_bottom == legend_y, (result_bottom, legend_y)
    if phase == "before_run":
        assert len(result_lines) == 1 and result_lines[0].startswith("No run yet"), result_lines
    if phase == "after_run":
        assert max_scroll == 0, (size, max_scroll, result_lines)
        assert result_lines and result_lines[0] == "NOTICES", result_lines[:2]
        heads = [line.split()[1] for line in result_lines if line[:1] in "●◈✗○□"]
        assert heads == ["source", "patch", "check", "write_out"], heads
        assert len(wrote) == 1 and len(wrote[0]) == 1, wrote
        assert wrote[0][0].strip().startswith("wrote ") and wrote[0][0].rstrip().endswith("fw_app_patched.s19"), wrote


@pytest.mark.parametrize("size", [(80, 24), (100, 40), (220, 40)])
def test_tc_b97_59_builder_below_the_range_run_reachable(tmp_path: Path, size) -> None:
    """TC-B97-59 (LLR-149.6, Builder arm): below the range ``tab`` from the
    panel top reaches ``#flow_run`` (<= 200 presses) and it lies inside the
    panel once focused; ``pagedown`` from scroll 0 brings it inside (<= 20);
    no two displayed buttons overlap.

    RED by mutation: ``overflow: hidden`` on the panel.
    """

    async def body(app, pilot, panel):
        panel.scroll_home(animate=False)
        app.query_one("#window_help_flow").focus()
        await settle(pilot, 2)
        presses = 0
        while (app.focused is None or app.focused.id != "flow_run") and presses < 200:
            await pilot.press("tab")
            presses += 1
        await _poll(pilot, lambda: panel.region.contains_region(panel.query_one("#flow_run").region))
        inside_tab = panel.region.contains_region(panel.query_one("#flow_run").region)
        panel.scroll_home(animate=False)
        panel.focus()
        await _poll(pilot, lambda: panel.scroll_y == 0)
        pages = 0
        while not panel.region.contains_region(panel.query_one("#flow_run").region) and pages < 20:
            await pilot.press("pagedown")
            await settle(pilot, 1)
            pages += 1
        inside_page = panel.region.contains_region(panel.query_one("#flow_run").region)
        buttons = [b.region for b in panel.query(Button) if is_displayed(b) and b.region.width]
        overlaps = [(a, b) for i, a in enumerate(buttons) for b in buttons[:i] if a.overlaps(b)]
        return presses, inside_tab, pages, inside_page, overlaps

    presses, inside_tab, pages, inside_page, overlaps = run_flow_builder(tmp_path, size, body)
    assert presses < 200 and inside_tab, (size, presses)
    assert pages < 20 and inside_page, (size, pages)
    assert overlaps == [], overlaps


# =========================================================================== #
# Inc-6 — the Flow Execution arms of TC-B97-34..38 and TC-B97-59
# =========================================================================== #

from tests.b97_fixtures import (  # noqa: E402
    flash_chain_demo,
    flash_evidence,
    fx_project,
    import_lanes,
    open_flow_execution,
    run_lanes,
    write_flow,
)

FX_THREE = ("patch_chain", "flash_chain", "err_chain")
FX_SIX = ("six_ok_a", "six_ok_b", "six_wait")
FX_CATEGORIES = ("nowrap-pipeline", "nowrap-ribbon", "nowrap-log", "nowrap-legend")
FX_PRIMARY = ("fx_import", "fx_mode", "fx_run", "fx_save", "fx_load")


def _fx_laid_out(panel) -> bool:
    """Flow Execution's layout pass ran for the viewport now shown (D24)."""
    scroll = panel.query("#fx_lanes_scroll")
    key = getattr(panel, "_layout_key", None)
    if not scroll or key is None:
        return not scroll or not hasattr(panel, "_layout_key")
    return key[0] == scroll.first().scrollable_content_region.width


def run_flow_execution(tmp_path: Path, size, body, *, stems=FX_THREE, run: bool = True, wide: bool = False):
    """Open Flow Execution at ``size`` with the A.5 project and ``stems``
    imported (a 60-cell change-doc ref on ``flash_chain`` when ``wide``), run
    them when ``run`` and return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await settle(pilot)
            project_dir = fx_project(app)
            names = list(stems)
            if wide:
                import shutil

                blocks = flash_chain_demo(project_dir)
                blocks[1] = type(blocks[1])(WIDE_REF)
                shutil.copyfile(project_dir / "calib_hotfix.json", project_dir / WIDE_REF)
                write_flow(project_dir, "wide_flash", blocks)
                names = ["wide_flash"]
            panel = await import_lanes(app, pilot, *names) if names else await open_flow_execution(app, pilot)
            if run and names:
                await run_lanes(app, pilot, panel, key=True)
            await _poll(pilot, lambda: _fx_laid_out(panel))
            await settle(pilot, 4)
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


def _columns(panel) -> dict:
    """``{j: {(x, width) per lane}}`` — card j's painted column in every lane."""
    columns = {}
    for lane in range(panel.lane_count()):
        j = 0
        while panel.query(f"#fx_card_{lane}_{j}"):
            region = panel.query_one(f"#fx_card_{lane}_{j}").region
            columns.setdefault(j, set()).add((region.x, region.width))
            j += 1
    return columns


def test_tc_b97_34_execution_cards_follow_four_resizes_in_columns(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, Execution painted arm; D24 / PC-4): in one session
    118x54 → 160x56 → 220x60 → 260x70 → 118x54 with a 4-block lane, a 6-block
    lane and a waiting lane, every card of every lane has the same painted
    width and card *j* starts at the same x in every lane (columns), the card
    width is non-decreasing and strictly greater at 220 than at 118, and back
    at 118x54 the columns equal the first reading.

    RED on main (P-22): no card columns. Mutations: ``n`` per lane (the
    4-block lane wider than the 6-block one → columns differ); the resize
    trigger removed.
    """

    async def body(app, pilot, panel):
        readings = []
        for size in ((118, 54), (160, 56), (220, 60), (260, 70), (118, 54)):
            await pilot.resize_terminal(*size)
            await _poll(pilot, lambda: app.size == size and _fx_laid_out(panel))
            await settle(pilot, 3)
            readings.append(_columns(panel))
        return readings

    readings = run_flow_execution(tmp_path, (118, 54), body, stems=("patch_chain", "six_ok_a", "flash_chain"))
    for columns in readings:
        assert columns and all(len(cells) == 1 for cells in columns.values()), columns
        assert len({width for cells in columns.values() for _x, width in cells}) == 1, columns
    widths = [next(iter(r[0]))[1] for r in readings]
    assert widths[:4] == sorted(widths[:4]) and widths[2] > widths[0], widths
    assert readings[0] == readings[-1]


def test_tc_b97_34_execution_card_width_holds_when_a_lane_starts_waiting(tmp_path: Path) -> None:
    """TC-B97-34 (D24 / PC-4): the Confirm reserve is taken whether or not a
    lane waits, so no card changes width or x when the pause paints.

    RED by mutation: the reserve taken only while a lane waits.
    """

    async def body(app, pilot, panel):
        before = _columns(panel)
        await run_lanes(app, pilot, panel, key=True)
        await _poll(pilot, lambda: panel.query_one("#fx_confirm_1").display)
        await settle(pilot, 4)
        return before, _columns(panel)

    before, after = run_flow_execution(tmp_path, (118, 54), body, run=False)
    assert before and all(len(cells) == 1 for cells in before.values()), f"guard: card columns painted: {before}"
    assert before == after, (before, after)


def test_tc_b97_34_execution_resize_while_hidden_rederives_on_show(tmp_path: Path) -> None:
    """TC-B97-34 (LLR-149.1, Execution hidden arm): resized to 220x60 while the
    Workspace is shown, then shown, Flow Execution paints the card width
    ``lane_layout`` derives from its measured viewport — wider than the
    21-cell minimum — and the same width as a session started at 220x60.

    RED by mutation: both layout triggers removed.
    """

    async def hidden(app, pilot, panel):
        app.action_show_screen("workspace")
        await settle(pilot, 2)
        await pilot.resize_terminal(220, 60)
        await _poll(pilot, lambda: app.size == (220, 60))
        app.action_show_screen("flow_execution")
        await _poll(pilot, lambda: _fx_laid_out(panel))
        await settle(pilot, 3)
        viewport = panel.query_one("#fx_lanes_scroll").scrollable_content_region.width
        return panel.query_one("#fx_card_0_0").region.width, viewport

    async def direct(app, pilot, panel):
        return panel.query_one("#fx_card_0_0").region.width

    width, viewport = run_flow_execution(tmp_path / "a", (118, 54), hidden, run=False)
    assert width == fs.lane_layout(viewport, 4).card_w and width > fs.CARD_MIN_W, (width, viewport)
    assert width == run_flow_execution(tmp_path / "b", (220, 60), direct, run=False)


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
@pytest.mark.parametrize("stems", [FX_THREE, FX_SIX], ids=["three", "six"])
def test_tc_b97_35_execution_no_horizontal_overflow(tmp_path: Path, size, stems) -> None:
    """TC-B97-35 (LLR-149.2, Execution arm): after the paused run, 0 displayed
    descendants of ``#fx_panel`` leave it on x over their clipped regions
    (P-52) — the 6-block lanes scroll inside ``#fx_lanes_scroll`` — over >= 10
    descendants, on both sides of the 120-column breakpoint.

    RED on main (P-10): the lanes overflow the panel (``max_scroll_x`` 77).
    """

    async def body(app, pilot, panel):
        return [w.id or type(w).__name__ for w in clipped_overflow(panel)], len(displayed_descendants(panel))

    offenders, population = run_flow_execution(tmp_path, size, body, stems=stems)
    assert offenders == [], (size, offenders)
    assert population >= 10


@pytest.mark.parametrize("size", RANGE_SAMPLES)
def test_tc_b97_36_execution_actions_inside_at_scroll_zero(tmp_path: Path, size) -> None:
    """TC-B97-36 (LLR-149.3, Execution arm; PC-24 at 118x53): after the
    paused 3-lane run, Import…, the mode switch, Run, Save Set and Load Set
    lie inside the panel region with the panel at its top.

    RED on main (P-11): ``#fx_save`` / ``#fx_load`` outside.
    """

    async def body(app, pilot, panel):
        panel.scroll_home(animate=False)
        await _poll(pilot, lambda: panel.scroll_y == 0)
        return {wid: panel.query_one(f"#{wid}").region for wid in FX_PRIMARY}, panel.region

    regions, panel_region = run_flow_execution(tmp_path, size, body)
    outside = [wid for wid, region in regions.items() if not panel_region.contains_region(region)]
    assert outside == [], (size, outside)


@pytest.mark.parametrize("size", [(118, 54), (119, 54), (120, 54), (160, 56), (220, 60), (260, 70)])
def test_tc_b97_37_execution_no_wrapped_row(tmp_path: Path, size) -> None:
    """TC-B97-37 (LLR-149.4, Execution arm): every member of the Execution
    no-wrap set — the lane heads, pending lines, card lines and cables, the
    ribbon, the run log and REQUIRED line, the legend, read from the DOM by
    category — paints one terminal row per logical line, and the ribbon keeps
    the session path's tail.

    RED by mutation: a 20-cell width on ``#fx_log`` (its lines wrap).
    """

    async def body(app, pilot, panel):
        members = {cat: [w for w in panel.query(f".{cat}") if is_displayed(w)] for cat in FX_CATEGORIES}
        wraps = []
        for widgets in members.values():
            for w in widgets:
                lines = str(w.render()).split("\n")
                height = w.get_content_height(w.content_region.size, app.size, w.content_region.width)
                if height != len(lines) or w.region.height < len(lines):
                    wraps.append((w.id or w.classes, height, len(lines), w.region.height))
        ribbon = [r.rstrip() for r in painted_rows(app, panel.query_one("#fx_name_strip")) if r.strip()]
        return {c: len(m) for c, m in members.items()}, wraps, ribbon, app.active_project_dir().name

    counts, wraps, ribbon, project = run_flow_execution(tmp_path, size, body)
    assert all(n >= 1 for n in counts.values()), counts
    assert wraps == [], wraps
    assert len(ribbon) == 1 and ribbon[0].endswith(project), ribbon


@pytest.mark.parametrize("size", [(160, 56), (163, 56), (220, 60), (223, 60), (260, 70)])
def test_tc_b97_38_execution_cards_take_their_width(tmp_path: Path, size) -> None:
    """TC-B97-38 (LLR-149.5, Execution width clause): with a 60-cell
    change-doc ref (clipped in its card, the guard) on a waiting lane, the
    lane row — its cards, cables and Confirm — leaves at most 2 void cells
    inside the lanes viewport; every card is at least 21 cells wide.

    RED by mutation: cards fixed at 21 cells.
    """

    async def body(app, pilot, panel):
        await _poll(pilot, lambda: panel.query_one("#fx_confirm_0").display)
        await settle(pilot, 3)
        view = panel.query_one("#fx_lanes_scroll").scrollable_content_region
        confirm = panel.query_one("#fx_confirm_0").region
        clipped = sum(r.count("…") for r in painted_rows(app, panel.query_one("#fx_lane_0_row")))
        return view.right - confirm.right, clipped, panel.query_one("#fx_card_0_0").region.width

    void, clipped, card_w = run_flow_execution(tmp_path, size, body, wide=True)
    assert clipped >= 1, "guard: the 60-cell ref clips in its card"
    assert void <= 2, (size, void)
    assert card_w >= 21


@pytest.mark.parametrize("size", [(118, 54), (118, 53), (220, 60)])
@pytest.mark.parametrize("phase", ["before_run", "after_run"])
def test_tc_b97_38_execution_height_goes_to_the_lanes(tmp_path: Path, size, phase) -> None:
    """TC-B97-38 (LLR-149.5, Execution height clause; PC-24 at 118x53): no
    panel row outside ``#fx_lanes_scroll`` is blank, and the lanes frame ends
    on the row of the first shown of ``#fx_required`` / ``#fx_log`` — before
    a run (one log line) and after the paused 3-lane run (REQUIRED + 6 log
    lines).

    RED on main (P-32): 3 blank rows outside the lanes frame.
    """

    async def body(app, pilot, panel):
        if phase == "after_run":
            await run_lanes(app, pilot, panel, key=True)
            await settle(pilot, 4)
        scroll = panel.query_one("#fx_lanes_scroll")
        blank = blank_panel_rows(app, panel, outside=scroll)
        assert blank == [], (size, phase, blank)
        first = next(w for w in (panel.query_one("#fx_required"), panel.query_one("#fx_log")) if w.display)
        return blank, scroll.region.bottom, first.region.y

    blank, bottom, first_y = run_flow_execution(tmp_path, size, body, run=False)
    assert blank == [], (size, phase, blank)
    assert bottom == first_y, (bottom, first_y)


@pytest.mark.parametrize("size", [(80, 24), (100, 40), (220, 40)])
def test_tc_b97_59_execution_below_the_range_actions_reachable(tmp_path: Path, size) -> None:
    """TC-B97-59 (LLR-149.6, Execution arm): below the range ``tab`` from the
    header reaches Run, Save Set and Load Set (<= 200 presses each) and each
    lies inside the panel once focused; ``pagedown`` from scroll 0 brings each
    inside (<= 20); no two displayed buttons overlap.

    RED by mutation: ``overflow: hidden`` on the panel.
    """

    async def body(app, pilot, panel):
        results = {}
        for wid in ("fx_run", "fx_save", "fx_load"):
            panel.scroll_home(animate=False)
            start = app.query("#window_help_flow_execution") or app.query("#fx_import")
            start.first().focus()
            await settle(pilot, 2)
            presses = 0
            while (app.focused is None or app.focused.id != wid) and presses < 200:
                await pilot.press("tab")
                presses += 1
            target = panel.query_one(f"#{wid}")
            await _poll(pilot, lambda: panel.region.contains_region(target.region))
            inside_tab = panel.region.contains_region(target.region)
            panel.scroll_home(animate=False)
            panel.focus()
            await _poll(pilot, lambda: panel.scroll_y == 0)
            pages = 0
            while not panel.region.contains_region(target.region) and pages < 20:
                await pilot.press("pagedown")
                await settle(pilot, 1)
                pages += 1
            results[wid] = (presses, inside_tab, pages, panel.region.contains_region(target.region))
        buttons = [b.region for b in panel.query(Button) if is_displayed(b) and b.region.width]
        overlaps = [(a, b) for i, a in enumerate(buttons) for b in buttons[:i] if a.overlaps(b)]
        return results, overlaps

    results, overlaps = run_flow_execution(tmp_path, size, body, stems=("patch_chain",))
    for wid, (presses, inside_tab, pages, inside_page) in results.items():
        assert presses < 200 and inside_tab, (size, wid, presses)
        assert pages < 20 and inside_page, (size, wid, pages)
    assert overlaps == [], overlaps
