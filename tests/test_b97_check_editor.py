"""Batch-97 Inc-3 — the Check Editor as a ledger + REPORT FIELDS card (HLR-145).

Covers LLR-145.1..145.10 (TC-B97-08..12, 43..46, 61) and the four acceptance
tests AT-B97-04, -05, -18, -21. Every assertion reads the shipped surface: the
composited strips (C-32, ``b97_probes.painted_rows``), the panel's own widgets,
the written ``.chk.json``. The A2L is the tracked demo (75 parameters with an
integer address, P-24), loaded through the app's own loader.

PC-11: each test opens with a clause that is observable on ``main``, and a
new id is looked up through ``need()`` (an assertion), never ``query_one``,
so a run on the base tree fails at a named assertion — not ``NoMatches``.
New module names are reached as ``sdb.<name>`` through ``getattr`` for the
same reason.
"""
from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest
from textual.widgets import Button, DataTable, Input, Label, Select

from s19_app.tui import screens_directionb as sdb
from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import (
    CE_IDS_9C7BEAF,
    DEMO_A2L,
    HOSTILE_CONTENT,
    HOSTILE_NAME,
    LONG_NAME,
    LONGEST_NAME,
    SIX_13A00,
    hostile_a2l,
    long_name_a2l,
    open_check_editor,
)
from tests.b97_probes import chip_style, is_displayed, painted_rows, settle

SIZES = ((118, 54), (220, 60))
DOCKED = ("check_validate_button", "check_write_button", "check_apply_ghost", "check_fields_count")
TABS = (
    ("check_tab_fields", "check_pane_fields"),
    ("check_tab_json", "check_pane_json"),
    ("check_tab_addendum", "check_pane_addendum"),
)
ADDRESS_RE = re.compile(r"0x[0-9A-F]{8}")


# --------------------------------------------------------------------------- #
# Drivers and readers
# --------------------------------------------------------------------------- #


def run(tmp_path: Path, size, body, *, a2l=DEMO_A2L, cover_image=False):
    """Open the Check Editor at ``size`` and return ``await body(app, pilot, panel)``."""

    async def _drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            panel = await open_check_editor(app, pilot, a2l=a2l, cover_image=cover_image)
            return await body(app, pilot, panel)

    return asyncio.run(_drive())


def need(root, selector: str):
    """The one widget ``selector`` names, or a named assertion failure."""
    found = list(root.query(selector))
    assert len(found) == 1, f"{selector}: expected exactly 1 widget, found {len(found)}"
    return found[0]


def column_span(table: DataTable, index: int) -> tuple:
    """(x0, x1) of column ``index``'s content cells, relative to the table region."""
    cols = table.ordered_columns
    x0 = sum(c.get_render_width(table) for c in cols[:index]) + table.cell_padding - int(table.scroll_x)
    return x0, x0 + cols[index].width


async def painted_table(app, pilot, table: DataTable) -> dict:
    """Row index -> the row's painted line, scrolling the table page by page."""
    out = {}
    table.scroll_to(y=0, animate=False)
    await settle(pilot, 2)
    for _ in range(40):
        lines = painted_rows(app, table)[1:]
        start = int(table.scroll_y)
        for offset, line in enumerate(lines):
            if start + offset < table.row_count:
                out.setdefault(start + offset, line)
        if len(out) >= table.row_count or start + len(lines) >= table.row_count:
            break
        table.scroll_to(y=start + len(lines), animate=False)
        await settle(pilot, 2)
    return out


def cell(line: str, span: tuple) -> str:
    return line[span[0]:span[1]].rstrip()


async def include(panel, pilot, name: str) -> None:
    """Highlight ``name``'s ledger row and press Include (the shipped control)."""
    table = panel.query_one("#check_param_table", DataTable)
    table.move_cursor(row=panel._visible_params.index(name))
    await settle(pilot, 2)
    panel.query_one("#check_param_include_button", Button).press()
    await settle(pilot, 2)


def fields_lines(app, panel) -> list:
    """The painted REPORT FIELDS lines after the head line: (mark, address, name).

    An absent ``#check_fields_lines`` reads as no line, so the caller's own
    clause is the one that fails on the base tree (PC-11).
    """
    holder = panel.query("#check_fields_lines")
    if not holder:
        return []
    rows = [r.rstrip() for r in painted_rows(app, holder.first())[1:] if r.strip()]
    parsed = []
    for row in rows:
        match = ADDRESS_RE.search(row)
        if match is None:
            parsed.append((row[:1], None, row))
            continue
        parsed.append((row[:1], match.group(0), row[match.end() + 1:].rstrip()))
    return parsed


def json_tab(panel):
    """The JSON tab's text parsed, or ``None`` when it is not a JSON document."""
    text = str(panel.query_one("#check_preview").render())
    try:
        return json.loads(text)
    except ValueError:
        return None


async def show_tab(panel, pilot, chip_id: str) -> None:
    """Press a card tab chip; absent on the base tree, so a no-op there and the
    caller's own clause names the failure (PC-11)."""
    chips = panel.query(f"#{chip_id}")
    if chips:
        chips.first().press()
        await settle(pilot, 2)


async def click_if(pilot, panel, selector: str) -> None:
    if panel.query(selector):
        await pilot.click(selector)
        await settle(pilot, 2)


# --------------------------------------------------------------------------- #
# TC-B97-08 — LLR-145.1
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_tc_b97_08_census_rows_and_one_docked_row(tmp_path: Path, size) -> None:
    """TC-B97-08 (LLR-145.1): the 31 shipped ids stay, the ledger holds the 75
    A2L rows, and Validate, Write, the APPLY ghost and the field count share
    ONE row inside the panel; no apply action exists. The 118x53 arm is the
    body height 118x54 keeps once the two-row key bar lands (PC-24).

    RED on main: Validate at y=35, the count at y=38 (two rows). Mutation: the
    count moved back to its own row.
    """

    async def body(app, pilot, panel):
        return (
            {panel.id} | {w.id for w in panel.query("*") if w.id},
            panel.query_one("#check_param_table", DataTable).row_count,
            {i: app.query_one(f"#{i}").region for i in DOCKED},
            panel.region,
            [b.id for b in panel.query(Button) if "apply" in (b.id or "")],
        )

    ids, rows, docked, panel_region, applies = run(tmp_path, size, body)
    assert len(CE_IDS_9C7BEAF) == 31
    assert CE_IDS_9C7BEAF - ids == set(), sorted(CE_IDS_9C7BEAF - ids)
    assert rows == 75
    assert len({r.y for r in docked.values()}) == 1, {i: r.y for i, r in docked.items()}
    for wid, region in docked.items():
        assert panel_region.contains_region(region), (wid, region, panel_region)
    assert applies == []


def test_tc_b97_08_tab_chips_nine_activations(tmp_path: Path) -> None:
    """TC-B97-08 (LLR-145.1, tab arm): each of the three tab chips switches the
    card by click, by ``enter`` and by ``space`` — 9 of 9 — showing its pane
    and hiding the other two.

    RED on main: no tab chip. Mutation: drop ``TabChip``'s ``space`` binding.
    """

    async def body(app, pilot, panel):
        switcher = need(panel, "#check_card_switcher")
        results = []
        for index, (chip_id, pane_id) in enumerate(TABS):
            other = TABS[(index + 1) % 3][0]
            for how in ("click", "enter", "space"):
                await show_tab(panel, pilot, other)
                chip = need(panel, f"#{chip_id}")
                if how == "click":
                    await pilot.click(f"#{chip_id}")
                else:
                    chip.focus()
                    await settle(pilot, 2)
                    await pilot.press(how)
                await settle(pilot, 2)
                shown = [p for _c, p in TABS if is_displayed(panel.query_one(f"#{p}"))]
                results.append((chip_id, how, switcher.current, shown))
        return results

    results = run(tmp_path, (118, 54), body)
    for chip_id, how, current, shown in results:
        pane = dict(TABS)[chip_id]
        assert current == pane and shown == [pane], (chip_id, how, current, shown)
    assert len(results) == 9


# --------------------------------------------------------------------------- #
# TC-B97-09 — LLR-145.2
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", SIZES)
def test_tc_b97_09_address_column_never_truncated(tmp_path: Path, size) -> None:
    """TC-B97-09 (LLR-145.2): the Address column lies inside the table at
    horizontal scroll 0 and every one of the 75 rows paints its full
    ``0x%08X`` address.

    RED on main (P-12): ``max_scroll_x`` 25 at 118x54. Mutation: a Parameter
    width that pushes the column out.
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        msx = table.max_scroll_x
        x0, x1 = column_span(table, 2)
        content_w = table.scrollable_content_region.width
        painted = await painted_table(app, pilot, table)
        expected = [panel._param_rows[n][0] for n in panel._visible_params]
        return msx, x1, content_w, painted, (x0, x1), expected

    msx, end, content_w, painted, span, expected = run(tmp_path, size, body)
    assert msx == 0, f"the table scrolls horizontally: max_scroll_x {msx}"
    assert end <= content_w, (end, content_w)
    assert len(painted) == 75
    wrong = [
        (i, cell(painted[i], span), f"0x{a:08X}")
        for i, a in enumerate(expected)
        if cell(painted[i], span) != f"0x{a:08X}"
    ]
    assert wrong == [], wrong[:5]


# --------------------------------------------------------------------------- #
# TC-B97-10 — LLR-145.3
# --------------------------------------------------------------------------- #


def _demo_names() -> list:
    text = DEMO_A2L.read_text(encoding="utf-8")
    return re.findall(r"/begin\s+(?:CHARACTERISTIC|MEASUREMENT)\s+(\S+)", text)


def test_tc_b97_10_layout_and_clip_units() -> None:
    """TC-B97-10 (LLR-145.3, layer 0): ``check_layout`` gives the measured
    widths (Parameter 42 / Fmt 6 / Fields 24 at 118; 89 / 11 / 56 at 220), and
    the two clips keep the discriminating part: first segment + ``…`` + tail
    for the ledger, ``…`` + tail for the Fields name.

    Why: P-38 — first segment + tail at W >= 42 leaves the 75 demo names
    distinct, a 40-cell column does not. RED on main: no ``check_layout``.
    Mutation: a head-keeping clip; a 40-cell floor.
    """
    layout = getattr(sdb, "check_layout", None)
    clip_param = getattr(sdb, "clip_param", None)
    clip_tail = getattr(sdb, "clip_tail", None)
    assert layout is not None and clip_param is not None and clip_tail is not None
    assert tuple(layout(68, 38, 11)) == (42, 6, "Fmt", 24, 17, 66)
    assert tuple(layout(120, 70, 11)) == (89, 11, "Fmt · Unit", 56, 49, 118)
    assert layout(68, 38, 0).fmt == 4, "never below u128's 4 cells"
    names = _demo_names()
    assert len(names) == 75
    clipped = [n for n in names if len(n) > 42]
    assert len(clipped) == 15, "15 demo names exceed 42 cells (guard)"
    for name in names:
        out = clip_param(name, 42)
        assert len(out) == min(len(name), 42), (name, out)
        if len(name) <= 42:
            assert out == name
            continue
        first = name.split(".")[0]
        assert out.startswith(first + "…") and out.count("…") == 1, out
        assert out.endswith(name[-(42 - len(first) - 1):]), out
    assert len({clip_param(n, 42) for n in names}) == 75, "0 equal cells at 42"
    assert len({clip_param(n, 40) for n in names}) < 75, "the instrument sees a collision at 40"
    exact = "A" * 42
    assert clip_param(exact, 42) == exact
    no_dot = "UNKNOWN" * 10
    out = clip_param(no_dot, 42)
    assert len(out) == 42 and out.count("…") == 1 and out.endswith(no_dot[-(42 - out.index("…") - 1):])
    for name in SIX_13A00:
        tail = clip_tail(name, 24)
        assert len(tail) == min(24, len(name))
        if len(name) > 24:
            assert tail == "…" + name[-23:]
    assert len({clip_tail(n, 24) for n in SIX_13A00}) == 6


def test_tc_b97_10_clips_measure_terminal_cells() -> None:
    """TC-B97-10 (LLR-145.3 / LLR-149.4, layer 0, code-reviewer F8): the three
    clips count terminal cells, not code points — a name of double-width
    characters clips to at most ``width`` cells and still keeps its tail.

    Why: a ``len()`` clip of a CJK name paints twice the column and pushes the
    Address out. RED on the pre-fold tree (``len()``); mutation: ``len`` back.
    """
    from rich.cells import cell_len

    wide = "ASAM.M." + "名前" * 20 + "末尾"
    for width in (12, 24, 42):
        out = sdb.clip_param(wide, width)
        assert width - 1 <= cell_len(out) <= width, (width, out, cell_len(out))
        assert out.startswith("ASAM…") and out.endswith("末尾"), out
        tail = sdb.clip_tail(wide, width)
        assert width - 1 <= cell_len(tail) <= width and tail.startswith("…") and tail.endswith("末尾"), tail
    unit = sdb._clip_fmt_unit("u16 単位単位単位", 8)
    assert cell_len(unit) <= 8 and unit.startswith("u16") and unit.endswith("…"), unit


@pytest.mark.parametrize("size", SIZES)
def test_tc_b97_10_painted_names_distinct_and_full_name_line(tmp_path: Path, size) -> None:
    """TC-B97-10 (LLR-145.3, integration): over the 75 painted Parameter cells
    every clipped cell is first segment + ``…`` + tail of exactly W cells, no
    two cells are equal, the 47-cell name paints in full at 220x60, the
    full-name line holds the highlighted 47-cell name and its address, and the
    six ``0x13A00`` Fields lines differ by name (name field 24 → 56 cells).

    RED on main: the table hard-clips by scrolling, so no cell is clipped
    with ``…`` (the guard). Mutation: head-keeping clip; card from the
    unfiltered list.
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        width = table.ordered_columns[1].width
        span = column_span(table, 1)
        painted = await painted_table(app, pilot, table)
        names = list(panel._visible_params)
        table.move_cursor(row=names.index(LONGEST_NAME))
        await settle(pilot, 2)
        holder = panel.query("#check_full_name_line")
        full_line = painted_rows(app, holder.first())[0] if holder else ""
        for name in SIX_13A00:
            await include(panel, pilot, name)
        return width, span, painted, names, full_line, fields_lines(app, panel), panel._param_rows[LONGEST_NAME][0]

    width, span, painted, names, full_line, fields, longest_addr = run(tmp_path, size, body)
    cells = {i: cell(painted[i], span) for i in range(len(names))}
    clipped = [i for i, n in enumerate(names) if len(n) > width]
    if size == (118, 54):
        assert len(clipped) >= 1, "guard: names wider than the column exist at 118"
    assert width >= 42
    for i in clipped:
        name, text = names[i], cells[i]
        first = name.split(".")[0]
        assert text.startswith(first + "…") and text.count("…") == 1, (name, text)
        assert text.endswith(name[-(width - len(first) - 1):]) and len(text) == width, (name, text)
    for i, name in enumerate(names):
        if i not in clipped:
            assert cells[i] == name, (name, cells[i])
    pairs = [(a, b) for a in range(len(names)) for b in range(a) if cells[a] == cells[b]]
    assert pairs == [], pairs[:3]
    if size == (220, 60):
        assert cells[names.index(LONGEST_NAME)] == LONGEST_NAME
    assert LONGEST_NAME in full_line and f"0x{longest_addr:08X}" in full_line, full_line
    assert len(fields) == 6 and len({f[2] for f in fields}) == 6, fields
    field_w = {(118, 54): 24, (220, 60): 56}[size]
    for mark, address, name_cell in fields:
        assert mark == "◆" and address == "0x00013A00", (mark, address)
        source = [n for n in SIX_13A00 if n.endswith(name_cell.lstrip("…"))]
        assert len(source) == 1, name_cell
        if len(source[0]) > field_w:
            assert name_cell == "…" + source[0][-(field_w - 1):], name_cell
        else:
            assert name_cell == source[0]


# --------------------------------------------------------------------------- #
# TC-B97-11 — LLR-145.4
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_tc_b97_11_every_button_is_a_one_row_chip(tmp_path: Path, size) -> None:
    """TC-B97-11 (LLR-145.4): every displayed button of the panel is one row
    tall — re-measured at 118x53 (PC-24) after the three-row memory form.

    RED on main: Validate is 3 rows (E-4). Mutation: restore Button's border.
    """

    async def body(app, pilot, panel):
        heights = {}
        for chip_id, _pane in TABS[:1] + TABS:
            if panel.query(f"#{chip_id}"):
                await show_tab(panel, pilot, chip_id)
            for b in panel.query(Button):
                if is_displayed(b):
                    heights[b.id] = b.region.height
        return heights

    heights = run(tmp_path, size, body)
    assert heights and all(h == 1 for h in heights.values()), heights
    assert len(heights) >= 8, f"guard: the panel's buttons were seen ({len(heights)})"


# --------------------------------------------------------------------------- #
# TC-B97-12 — LLR-145.5
# --------------------------------------------------------------------------- #


def _payload_spans(text) -> list:
    return [s for s in getattr(text, "spans", []) if re.search(r"link|click|^bold$|^red$", str(s.style))]


def test_tc_b97_12_hostile_names_render_literally(tmp_path: Path) -> None:
    """TC-B97-12 (LLR-145.5): a markup-laden A2L name and a markup-laden spec
    file name read literally on the four surfaces — ledger cell, REPORT FIELDS
    line, JSON tab and spec row — with 0 spans from the payload and 0 control
    characters painted.

    RED: the mutation renders one surface with ``Text.from_markup``.
    """

    async def body(app, pilot, panel):
        patches = app._patches_dir()
        patches.mkdir(parents=True, exist_ok=True)
        (patches / f"{HOSTILE_NAME}.chk.json").write_text("{}", encoding="utf-8")
        app.action_show_screen("workspace")
        await settle(pilot)
        app.action_show_screen("check_editor")
        await settle(pilot, 6)
        table = panel.query_one("#check_param_table", DataTable)
        index = panel._visible_params.index(HOSTILE_CONTENT)
        ledger_cell = table.get_row_at(index)[1]
        await include(panel, pilot, HOSTILE_CONTENT)
        lines = need(panel, "#check_fields_lines").render()
        await show_tab(panel, pilot, "check_tab_json")
        json_painted = "\n".join(painted_rows(app, panel.query_one("#check_preview")))
        doc = json_tab(panel)
        select = panel.query_one("#check_spec_file_select", Select)
        option = [label for label, _v in select._options if "b97" in str(getattr(label, "plain", label))]
        return ledger_cell, lines, json_painted, doc, option

    hostile = hostile_a2l(tmp_path)
    ledger_cell, lines, json_painted, doc, option = run(tmp_path, (118, 54), body, a2l=hostile)
    assert doc is not None and [e["name"] for e in doc["entries"]] == [HOSTILE_CONTENT]
    surfaces = {
        "ledger": ledger_cell,
        "fields": lines,
        "spec": option[0] if option else None,
    }
    for surface, text in surfaces.items():
        assert text is not None and hasattr(text, "spans"), surface
        plain = text.plain
        assert "[" in plain and "]" in plain, (surface, plain)
        assert _payload_spans(text) == [], (surface, text.spans)
        assert not [c for c in plain if ord(c) < 0x20 and c != "\n"], (surface, plain)
    assert "[@click=app.quit]" in surfaces["fields"].plain, "the tail-kept name keeps its brackets"
    assert HOSTILE_NAME in surfaces["spec"].plain
    assert "[bold]x[/]y" in json_painted and "\x07" not in json_painted


# --------------------------------------------------------------------------- #
# TC-B97-43 — LLR-145.6
# --------------------------------------------------------------------------- #


async def _add_memory_row(panel, pilot, address: str, label: str, size: str) -> None:
    panel.query_one("#check_mem_address_input", Input).value = address
    panel.query_one("#check_mem_label_input", Input).value = label
    panel.query_one("#check_mem_size_input", Input).value = size
    panel.query_one("#check_mem_add_button", Button).press()
    await settle(pilot, 2)


def test_tc_b97_43_fields_hold_exactly_the_included(tmp_path: Path) -> None:
    """TC-B97-43 (LLR-145.6): two included parameters and one memory row give
    exactly three Fields lines (``◆`` ×2, ``▪`` ×1) in inclusion order, the JSON
    tab parses to the same three addresses, the count reads 3, the Addendum tab
    shows ``#check_addendum_preview``; including then excluding a parameter
    removes its line.

    RED on main: the JSON preview is not a JSON document; no Fields tab.
    Mutation: the card fed from the unfiltered parameter list (75 lines).
    """

    async def body(app, pilot, panel):
        names = list(panel._visible_params)
        a1, a2 = names[1], names[4]
        doc_before = json_tab(panel)
        await include(panel, pilot, a1)
        await include(panel, pilot, a2)
        await _add_memory_row(panel, pilot, "0x100", "m1", "4")
        doc = json_tab(panel)
        fields = fields_lines(app, panel)
        count = str(panel.query_one("#check_fields_count").render())
        await show_tab(panel, pilot, "check_tab_addendum")
        addendum_shown = is_displayed(panel.query_one("#check_addendum_preview"))
        await show_tab(panel, pilot, "check_tab_fields")
        await include(panel, pilot, a1)
        after_exclude = fields_lines(app, panel)
        rows = panel._param_rows
        return doc_before, doc, fields, count, addendum_shown, after_exclude, rows[a1][0], rows[a2][0]

    doc_before, doc, fields, count, addendum_shown, after_exclude, a1, a2 = run(tmp_path, (118, 54), body)
    assert doc_before is not None, "the JSON tab must hold a JSON document"
    assert doc_before["entries"] == [], "empty arm: nothing included -> entries []"
    assert doc is not None
    assert [e["address"] for e in doc["entries"]] == [f"0x{a1:08X}", f"0x{a2:08X}", "0x00000100"]
    assert [(m, a) for m, a, _n in fields] == [("◆", f"0x{a1:08X}"), ("◆", f"0x{a2:08X}"), ("▪", "0x00000100")]
    assert count.startswith("3 fields"), count
    assert addendum_shown
    assert [(m, a) for m, a, _n in after_exclude] == [("◆", f"0x{a2:08X}"), ("▪", "0x00000100")]


def test_tc_b97_43_empty_state_and_json_cap() -> None:
    """TC-B97-43 (LLR-145.6, cap arm, layer 0): the JSON tab text is capped at
    ``JSON_TAB_LINE_CAP`` lines plus one note line ``showing 5000 of M lines``;
    5000 lines pass unchanged.

    RED on main: no cap function. Mutation: the cap removed.
    """
    cap = getattr(sdb, "cap_json_lines", None)
    assert cap is not None and getattr(sdb, "JSON_TAB_LINE_CAP", None) == 5000
    exact = "\n".join(f"line {i}" for i in range(5000))
    assert cap(exact) == exact
    over = exact + "\nline 5000"
    lines = cap(over).split("\n")
    assert len(lines) == 5001 and lines[:5000] == exact.split("\n")
    assert lines[-1] == "showing 5000 of 5001 lines"


def test_tc_b97_43_memory_lines_name_the_address_once(tmp_path: Path) -> None:
    """TC-B97-43 (LLR-145.6, memory arm; ux-reviewer M1, code-reviewer F6): a
    memory row with no typed label paints ``▪ <address> u32 memory row`` in
    the Fields tab and ``—`` in the memory table's Label cell — the address is
    shown once, not again inside ``field @ 0x…`` — while the spec keeps the
    stored name; a typed label wider than its field keeps its HEAD (labels are
    labels, LLR-149.4), with one ``…``.

    RED on the pre-fold tree: the default name painted twice; the label clipped
    by its tail. Mutation: the default name painted; ``clip_tail`` on labels.
    """
    long_label = "LABEL_HEAD_" + "X" * 60 + "_END"

    async def body(app, pilot, panel):
        await _add_memory_row(panel, pilot, "0x100", "", "4")
        await _add_memory_row(panel, pilot, "0x200", long_label, "2")
        fields = fields_lines(app, panel)
        mem = panel.query_one("#check_mem_table", DataTable)
        span = column_span(mem, 1)
        labels = [cell(r, span) for r in painted_rows(app, mem)[1:] if r.strip()]
        painted = "\n".join(painted_rows(app, need(panel, "#check_fields_lines")))
        return fields, labels, painted, json_tab(panel)

    fields, labels, painted, doc = run(tmp_path, (118, 54), body)
    assert [(m, a) for m, a, _n in fields] == [("▪", "0x00000100"), ("▪", "0x00000200")], fields
    assert fields[0][2] == "u32 memory row", fields[0]
    second = fields[1][2]
    assert second.startswith("u16 LABEL_HEAD_") and second.endswith("…") and second.count("…") == 1, second
    assert "field @" not in painted, painted
    assert labels[0] == "—" and labels[1].startswith("LABEL_HEAD_"), labels
    assert [e["name"] for e in doc["entries"]] == ["field @ 0x00000100", long_label], "the spec is unchanged"


def test_tc_b97_43_counts_agree_in_number_and_the_hint_reads_whole(tmp_path: Path) -> None:
    """TC-B97-43 (LLR-145.6, head line; ux-reviewer L3 / L4): the Fields head and
    the docked count use the singular for one (``1 field: 1 param · 0 memory
    rows``, ``1 field → report``), and the status hint reads in full on its
    row with no ``…``.

    RED on the pre-fold tree: ``1 fields: 1 params``. Mutation: plural always.
    """

    async def body(app, pilot, panel):
        hint = painted_rows(app, panel.query_one("#check_status"))[0].strip()
        await include(panel, pilot, panel._visible_params[1])
        one = (
            painted_rows(app, need(panel, "#check_fields_lines"))[0].strip(),
            str(panel.query_one("#check_fields_count").render()),
        )
        await include(panel, pilot, panel._visible_params[4])
        await _add_memory_row(panel, pilot, "0x100", "m1", "1")
        three = painted_rows(app, need(panel, "#check_fields_lines"))[0].strip()
        return hint, one, three, panel._STATUS_HINT

    hint, one, three, expected_hint = run(tmp_path, (118, 54), body)
    assert one == ("1 field: 1 param · 0 memory rows", "1 field → report"), one
    assert three == "3 fields: 2 params · 1 memory row", three
    assert hint == expected_hint and "…" not in hint and " vs " not in hint, hint


# --------------------------------------------------------------------------- #
# TC-B97-44 — LLR-145.7
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_tc_b97_44_memory_inputs_labelled_inside_the_fields_tab(tmp_path: Path, size) -> None:
    """TC-B97-44 (LLR-145.7): the memory table, its three inputs and two chips
    sit inside the Fields pane, and each input has a displayed label on its row,
    left of it, naming its field: ``Address``, ``Label``, ``Size (bytes)`` (D19).

    Form arm (operator decision at the Inc-3 gate, LED-2026-10-19-batch-97.14;
    ux-reviewer M2): one row per field — the three inputs on three consecutive
    rows, the labels in one fixed column wide enough for ``Size (bytes)``, the
    Address and Label inputs equally wide (``1fr``), and one blank spacer row
    in the card before ``MEMORY LOCATIONS`` and before the status line. Run at
    118x54 and at the 118x53 body of the two-row key bar (PC-24).

    RED on main: placeholders only, no label widget. RED on the pre-fold tree:
    Label and Size share a row; no spacer. Mutation: Size back on the Label
    row; a spacer removed.
    """
    inputs = {
        "check_mem_address_input": "Address",
        "check_mem_label_input": "Label",
        "check_mem_size_input": "Size (bytes)",
    }

    async def body(app, pilot, panel):
        labels = {}
        for input_id in inputs:
            box = panel.query_one(f"#{input_id}").region
            labels[input_id] = [
                str(lab.render()).strip()
                for lab in panel.query(Label)
                if is_displayed(lab) and lab.region.y == box.y and lab.region.right <= box.x
            ]
        holder = panel.query("#check_pane_fields")
        ids = list(inputs) + ["check_mem_table", "check_mem_add_button", "check_mem_remove_button"]
        inside = {
            i: bool(holder) and holder.first().region.contains_region(panel.query_one(f"#{i}").region)
            for i in ids
        }
        column = panel.query_one("#check_mem_table", DataTable)
        headers = [str(c.label) for c in column.ordered_columns]
        boxes = {i: panel.query_one(f"#{i}").region for i in inputs}
        label_boxes = {
            i: [lab.region for lab in panel.query(Label) if is_displayed(lab) and lab.region.y == boxes[i].y and lab.region.right <= boxes[i].x]
            for i in inputs
        }
        pane = panel.query_one("#check_pane_fields")
        rows = painted_rows(app, pane)
        title_y = panel.query_one("#check_pane_fields .ce-title").region.y
        status_y = panel.query_one("#check_status").region.y
        spacers = [rows[y - pane.region.y].strip() for y in (title_y - 1, status_y - 1)]
        return labels, inside, headers, boxes, label_boxes, spacers

    labels, inside, headers, boxes, label_boxes, spacers = run(tmp_path, size, body)
    for input_id, name in inputs.items():
        assert labels[input_id] and labels[input_id][-1] == name, (input_id, labels[input_id])
    assert all(inside.values()), inside
    assert headers == ["Address", "Label", "Fmt"]
    ys = [boxes[i].y for i in inputs]
    assert ys == [ys[0], ys[0] + 1, ys[0] + 2], f"one row per field: {ys}"
    lefts = {label_boxes[i][-1].x for i in inputs}
    widths = {label_boxes[i][-1].width for i in inputs}
    assert len(lefts) == 1 and len(widths) == 1 and min(widths) >= len("Size (bytes)"), (lefts, widths)
    assert len({boxes[i].x for i in inputs}) == 1, "the inputs start in one column"
    address_w, label_w = boxes["check_mem_address_input"].width, boxes["check_mem_label_input"].width
    assert address_w == label_w and address_w > boxes["check_mem_size_input"].width >= 3, boxes
    assert spacers == ["", ""], f"a blank spacer row before MEMORY LOCATIONS and the status line: {spacers}"


# --------------------------------------------------------------------------- #
# TC-B97-45 — LLR-145.8
# --------------------------------------------------------------------------- #

HEADER = ("open_folder_checks_editor", "window_help_check_editor")
GROUPS_BY_TAB = {
    "check_tab_fields": (
        "check_mem_table", "check_mem_address_input", "check_mem_label_input",
        "check_mem_size_input", "check_mem_add_button", "check_mem_remove_button",
    ),
    "check_tab_json": ("check_pane_json",),
    "check_tab_addendum": ("check_pane_addendum",),
}


def _groups(tab: str) -> list:
    return [
        HEADER,
        ("check_param_filter",),
        ("check_param_table",),
        ("check_param_include_button",),
        tuple(c for c, _p in TABS),
        GROUPS_BY_TAB[tab],
        ("check_spec_file_select", "check_file_name_input"),
        ("check_validate_button", "check_write_button"),
    ]


def _reference_set(app, panel) -> set:
    """Every displayed, enabled control of the panel and its header, by type
    (contract §4 method (b)), independent of ``can_focus``."""
    from textual.widgets import TextArea

    screen = app.query_one("#screen_check_editor")
    found = set()
    for root in list(screen.query(".db-screen-header")) + [panel]:
        for w in root.query("*"):
            if not w.id or not is_displayed(w) or w.disabled:
                continue
            if isinstance(w, (Button, Input, Select, DataTable, TextArea)):
                found.add(w.id)
    for scroll in ("check_pane_json", "check_pane_addendum"):
        if panel.query(f"#{scroll}") and is_displayed(panel.query_one(f"#{scroll}")):
            found.add(scroll)
    return found


def test_tc_b97_45_keyboard_order_enter_space_and_chip_states(tmp_path: Path) -> None:
    """TC-B97-45 (LLR-145.8): per tab state the focus chain runs header chips →
    filter → ledger → include → tab chips → the active tab's controls → spec
    row → docked row with no inversion and no displayed control left out;
    ``enter`` acts on one member of each button group; ``space`` on a
    highlighted ledger row includes it (N+1) and again excludes it (N); a
    focused chip paints differently from an unfocused one and a tab chip's
    unfocused, focused and selected styles are pairwise distinct.

    RED on main (P-33, P-43): no header chip and no tab chip in the chain;
    ``DataTable`` binds no ``space``. Mutation: ``can_focus = False`` on a
    control; drop ``IncludeTable``'s binding.
    """

    async def body(app, pilot, panel):
        report = {"order": {}, "missing": {}}
        for tab in GROUPS_BY_TAB:
            if panel.query(f"#{tab}"):
                await show_tab(panel, pilot, tab)
            chain = [w.id for w in app.screen.focus_chain if w.id]
            groups = _groups(tab)
            index = {wid: g for g, ids in enumerate(groups) for wid in ids}
            seq = [index[w] for w in chain if w in index]
            report["order"][tab] = (seq, [sum(1 for w in chain if w in ids) for ids in groups])
            report["missing"][tab] = sorted(_reference_set(app, panel) - set(chain))
        # enter: one member of each button group
        table = panel.query_one("#check_param_table", DataTable)
        count = panel.query_one("#check_fields_count")
        enters = {}
        table.move_cursor(row=2)
        await settle(pilot, 2)
        panel.query_one("#check_param_include_button").focus()
        await pilot.press("enter")
        await settle(pilot, 2)
        enters["include"] = str(count.render())
        if panel.query("#check_tab_json"):
            panel.query_one("#check_tab_json").focus()
            await pilot.press("enter")
            await settle(pilot, 2)
        switchers = panel.query("#check_card_switcher")
        enters["tab"] = switchers.first().current if switchers else None
        await show_tab(panel, pilot, "check_tab_fields")
        panel.query_one("#check_mem_address_input", Input).value = "0x200"
        panel.query_one("#check_mem_size_input", Input).value = "2"
        panel.query_one("#check_mem_add_button").focus()
        await pilot.press("enter")
        await settle(pilot, 2)
        enters["add"] = panel.query_one("#check_mem_table", DataTable).row_count
        panel.query_one("#check_validate_button").focus()
        await pilot.press("enter")
        await settle(pilot, 3)
        enters["validate"] = str(panel.query_one("#check_status").render())
        enters["help"] = None
        if app.query("#window_help_check_editor"):
            app.query_one("#window_help_check_editor").focus()
            await pilot.press("enter")
            await settle(pilot, 2)
            enters["help"] = type(app.screen).__name__
            await pilot.press("escape")
            await settle(pilot, 2)
        # space on a highlighted ledger row, twice
        table.focus()
        table.move_cursor(row=3)
        await settle(pilot, 2)
        spaces = [str(count.render())]
        for _ in range(2):
            await pilot.press("space")
            await settle(pilot, 2)
            spaces.append(str(count.render()))
        # chip states
        filt = panel.query_one("#check_param_filter")
        states = {}
        for chip_id in ("check_tab_json", "check_param_include_button", "check_write_button"):
            if not panel.query(f"#{chip_id}"):
                continue
            chip = panel.query_one(f"#{chip_id}")
            filt.focus()
            await settle(pilot, 2)
            unfocused = chip_style(app, chip)
            chip.focus()
            await settle(pilot, 2)
            focused = chip_style(app, chip)
            states[chip_id] = [unfocused, focused]
        await show_tab(panel, pilot, "check_tab_json")
        filt.focus()
        await settle(pilot, 2)
        if "check_tab_json" in states:
            json_chip = panel.query_one("#check_tab_json")
            states["check_tab_json"].append(chip_style(app, json_chip))
            json_chip.focus()
            await settle(pilot, 2)
            states["check_tab_json"].append(chip_style(app, json_chip))
        return report, enters, spaces, states

    report, enters, spaces, states = run(tmp_path, (118, 54), body)
    for tab, (seq, members) in report["order"].items():
        assert all(n >= 1 for n in members), (tab, members)
        assert seq == sorted(seq), (tab, seq)
        assert report["missing"][tab] == [], (tab, report["missing"][tab])
    assert enters["include"].startswith("1 field "), enters
    assert enters["tab"] == "check_pane_json", enters
    assert enters["add"] == 1, enters
    assert enters["validate"], enters
    assert enters["help"] == "WindowHelpScreen", enters
    counts = [int(s.split(" ")[0]) for s in spaces]
    assert counts == [counts[0], counts[0] + 1, counts[0]], spaces
    for chip_id, styles in states.items():
        assert styles[0] != styles[1], (chip_id, styles)
    # unfocused, focused, selected, focused+selected: pairwise distinct (the
    # last is code-reviewer F10 — a focused selected tab must not look like a
    # focused unselected one).
    tab_states = states.get("check_tab_json", [])
    assert len(set(tab_states)) == 4, tab_states


def test_tc_b97_45_enter_on_the_ledger_toggles_inclusion(tmp_path: Path) -> None:
    """TC-B97-45 (LLR-145.8, ux-reviewer L1): ``enter`` on a highlighted ledger
    row includes it (N+1) and again excludes it (N), like ``space``, and the
    screen stays the Check Editor.

    RED on the pre-fold tree: ``enter`` selects the row and includes nothing.
    Mutation: the ``enter`` binding dropped from ``IncludeTable``.
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        count = panel.query_one("#check_fields_count")
        table.focus()
        table.move_cursor(row=3)
        await settle(pilot, 2)
        seen = [str(count.render())]
        for _ in range(2):
            await pilot.press("enter")
            await settle(pilot, 2)
            seen.append(str(count.render()))
        return seen, app.query_one("#screen_check_editor").display

    seen, shown = run(tmp_path, (118, 54), body)
    counts = [int(s.split(" ")[0]) for s in seen]
    assert counts == [counts[0], counts[0] + 1, counts[0]], seen
    assert shown


# --------------------------------------------------------------------------- #
# TC-B97-46 — LLR-145.9
# --------------------------------------------------------------------------- #


def test_tc_b97_46_one_filled_element(tmp_path: Path) -> None:
    """TC-B97-46 (LLR-145.9): on each of the three card tabs the only filled
    element besides the ledger is ``#check_write_button``, and the active tab
    chip's background differs from the fill.

    RED on main: no filled element. Mutation: a second ``variant="primary"``.
    """

    async def body(app, pilot, panel):
        out = {}
        for chip_id, _pane in TABS:
            if panel.query(f"#{chip_id}"):
                await show_tab(panel, pilot, chip_id)
            panel.query_one("#check_param_filter").focus()
            await settle(pilot, 2)
            filled = [
                w.id
                for w in panel.query("*")
                if is_displayed(w)
                and (w.has_class("fill-accent") or (isinstance(w, Button) and w.variant == "primary"))
            ]
            chip_bg = chip_style(app, panel.query_one(f"#{chip_id}"))[1] if panel.query(f"#{chip_id}") else None
            write_bg = chip_style(app, panel.query_one("#check_write_button"))[1]
            out[chip_id] = (filled, chip_bg, write_bg)
        return out

    for chip_id, (filled, chip_bg, write_bg) in run(tmp_path, (118, 54), body).items():
        assert filled == ["check_write_button"], (chip_id, filled)
        assert chip_bg != write_bg, (chip_id, chip_bg, write_bg)


# --------------------------------------------------------------------------- #
# TC-B97-61 — LLR-145.10
# --------------------------------------------------------------------------- #

HOMES = {
    "check_left_column": (("check_param_filter", "check_param_table", "check_param_include_button"), (), None),
    "check_pane_fields": (
        ("check_mem_table", "check_mem_address_input", "check_mem_label_input",
         "check_mem_size_input", "check_mem_add_button", "check_mem_remove_button"),
        ("check_fields_lines", "check_status"),
        "check_tab_fields",
    ),
    "check_pane_json": (("check_pane_json",), ("check_preview",), "check_tab_json"),
    "check_pane_addendum": (("check_pane_addendum",), ("check_addendum_preview",), "check_tab_addendum"),
    "check_spec_file_row": (("check_spec_file_select", "check_file_name_input"), (), None),
    "check_dock": (("check_validate_button", "check_write_button"), ("check_apply_ghost", "check_fields_count"), None),
}


@pytest.mark.parametrize("size", SIZES)
def test_tc_b97_61_every_control_displayed_in_its_home(tmp_path: Path, size) -> None:
    """TC-B97-61 (LLR-145.10): per tab state each control and read-out of the
    table is displayed inside its home when its condition holds, every
    displayed control is in the focus chain (15 controls, 6 read-outs), every
    control-typed shipped id but the toggle is in the table (13), and
    ``#check_preview_toggle_button`` is mounted and not displayed.

    RED on main: the toggle is displayed. Mutation: a control left under a
    hidden pane; a shipped control dropped from the table.
    """
    from textual.widgets import TextArea

    async def body(app, pilot, panel):
        toggle = panel.query_one("#check_preview_toggle_button")
        toggle_displayed = is_displayed(toggle)
        typed = {
            i for i in CE_IDS_9C7BEAF
            if isinstance(app.query_one(f"#{i}"), (Button, Input, Select, TextArea, DataTable))
        }
        seen_controls, seen_readouts, problems = set(), set(), []
        for chip_id, _pane in TABS:
            if panel.query(f"#{chip_id}"):
                await show_tab(panel, pilot, chip_id)
            chain = {w.id for w in app.screen.focus_chain}
            for home_id, (controls, readouts, when) in HOMES.items():
                if when is not None and when != chip_id:
                    continue
                homes = panel.query(f"#{home_id}")
                if not homes:
                    problems.append((chip_id, home_id, "home missing"))
                    continue
                home = homes.first()
                for wid in controls + readouts:
                    w = panel.query_one(f"#{wid}")
                    # A read-out inside a scroll-view home is read by its
                    # clipped region (§1.3): the part outside the viewport is
                    # reachable by scrolling, not outside the home.
                    region = w.region
                    if home.styles.overflow_x in ("auto", "scroll") and w is not home:
                        region = region.intersection(home.content_region)
                    if not (is_displayed(w) and region.width and home.region.contains_region(region)):
                        problems.append((chip_id, home_id, wid, w.region, home.region))
                    if wid in controls:
                        seen_controls.add(wid)
                        if wid not in chain:
                            problems.append((chip_id, wid, "not in focus chain"))
                    else:
                        seen_readouts.add(wid)
        return toggle_displayed, typed, seen_controls, seen_readouts, problems

    toggle_displayed, typed, controls, readouts, problems = run(tmp_path, size, body)
    assert toggle_displayed is False, "the addendum toggle is mounted, not displayed"
    assert problems == [], problems[:5]
    assert len(controls) == 15 and len(readouts) == 6, (len(controls), len(readouts))
    column = {c for home in HOMES.values() for c in home[0]}
    shipped = typed - {"check_preview_toggle_button"}
    assert len(shipped) == 13 and shipped <= column, sorted(shipped - column)


# --------------------------------------------------------------------------- #
# Acceptance — AT-B97-04, -05, -18, -21
# --------------------------------------------------------------------------- #


async def _focus_by_tab(app, pilot, target: str, bound: int = 60) -> bool:
    for _ in range(bound):
        if app.focused is not None and app.focused.id == target:
            return True
        await pilot.press("tab")
        await settle(pilot, 1)
    return app.focused is not None and app.focused.id == target


@pytest.mark.parametrize("size", SIZES)
def test_at_b97_04_engineer_reads_every_address_and_includes_one(tmp_path: Path, size) -> None:
    """AT-B97-04 (HLR-145): through the rail key ``=``, ``down`` ×2 and a click
    on Include parameter, the engineer reads all 75 addresses in full with no
    horizontal scroll, tells every parameter name apart, and sees the field
    count rise by one.

    RED on main (P-12): the Address column is cut at 118x54.
    """

    async def body(app, pilot, panel):
        await pilot.press("equals_sign")
        await settle(pilot, 4)
        table = panel.query_one("#check_param_table", DataTable)
        span_a, span_p = column_span(table, 2), column_span(table, 1)
        painted = await painted_table(app, pilot, table)
        expected = [panel._param_rows[n][0] for n in panel._visible_params]
        before = str(panel.query_one("#check_fields_count").render())
        reached = await _focus_by_tab(app, pilot, "check_param_table")
        await pilot.press("down", "down")
        await settle(pilot, 2)
        await pilot.click("#check_param_include_button")
        await settle(pilot, 3)
        after = str(panel.query_one("#check_fields_count").render())
        return painted, expected, span_a, span_p, before, after, reached

    painted, expected, span_a, span_p, before, after, reached = run(tmp_path, size, body)
    full = [i for i, a in enumerate(expected) if cell(painted[i], span_a) == f"0x{a:08X}"]
    assert len(full) == 75, f"{len(full)} of 75 addresses painted in full"
    names = [cell(painted[i], span_p) for i in range(75)]
    assert len(set(names)) == 75, "0 equal Parameter cells for different names"
    assert reached
    assert int(after.split()[0]) == int(before.split()[0]) + 1, (before, after)


@pytest.mark.parametrize("size", [(118, 54), (118, 53)])
def test_at_b97_04_empty_ledger_line_and_dock_inside(tmp_path: Path, size) -> None:
    """AT-B97-04 (HLR-145, empty arm + PC-24 docked-row clause): with no A2L the
    ledger region shows one English line and the docked row stays inside the
    panel, at 118x54 and at the 118x53 body the two-row key bar will leave.

    RED on main: no empty-state line under the ledger.
    """

    async def body(app, pilot, panel):
        left = panel.query_one("#check_left_column")
        text = [r.strip() for r in painted_rows(app, left) if r.strip()]
        docked = [panel.query_one(f"#{i}").region for i in DOCKED]
        return text, docked, panel.region

    text, docked, panel_region = run(tmp_path, size, body, a2l=None)
    lines = [t for t in text if "A2L" in t and "load" in t.lower()]
    assert len(lines) == 1, text
    assert all(panel_region.contains_region(r) for r in docked)
    assert len({r.y for r in docked}) == 1


def test_at_b97_05_hostile_parameter_reads_literally(tmp_path: Path) -> None:
    """AT-B97-05 (HLR-145): the engineer filters for the markup-laden parameter
    of ``hostile.a2l``, includes it, and reads its name literally on the
    ledger, the full-name line, the REPORT FIELDS card and the JSON tab — no
    markup error, no styled span from the payload, no control character.

    RED: the mutation renders the ledger cell with ``Text.from_markup``.
    """

    async def body(app, pilot, panel):
        await pilot.press("equals_sign")
        await settle(pilot, 4)
        await _focus_by_tab(app, pilot, "check_param_filter")
        await pilot.press(*"b97")
        await settle(pilot, 3)
        await pilot.click("#check_param_include_button")
        await settle(pilot, 3)
        out = {
            "ledger": painted_rows(app, panel.query_one("#check_param_table"))[1],
            "full_name": painted_rows(app, need(panel, "#check_full_name_line"))[0],
            "fields": "\n".join(painted_rows(app, need(panel, "#check_fields_lines"))),
        }
        await pilot.click("#check_tab_json")
        await settle(pilot, 2)
        out["json"] = "\n".join(painted_rows(app, panel.query_one("#check_preview")))
        out["fields_spans"] = need(panel, "#check_fields_lines").render().spans
        return out

    out = run(tmp_path, (118, 54), body, a2l=hostile_a2l(tmp_path))
    for surface in ("ledger", "full_name", "fields", "json"):
        assert "b97[bold]x[/]y" in out[surface] or "[@click=app.quit]" in out[surface], (surface, out[surface])
        assert not [c for c in out[surface] if ord(c) < 0x20 and c != "\n"], surface
    assert [s for s in out["fields_spans"] if re.search(r"link|click", str(s.style))] == []


def test_at_b97_18_first_task_from_the_keyboard(tmp_path: Path) -> None:
    """AT-B97-18 (HLR-145): keys only — tab to the filter, type, tab to the
    ledger, ``down``, ``space`` includes the row (its Fields line appears), tab
    to Write, ``enter`` — and the written ``.chk.json`` parses to that address.

    RED on main (P-43): ``space`` does nothing on the ledger.
    """

    async def body(app, pilot, panel):
        await pilot.press("equals_sign")
        await settle(pilot, 4)
        assert await _focus_by_tab(app, pilot, "check_param_filter")
        await pilot.press(*"UWORD.IDENTICAL")
        await settle(pilot, 3)
        assert await _focus_by_tab(app, pilot, "check_param_table")
        await pilot.press("down")
        await settle(pilot, 2)
        name = panel._visible_params[panel.query_one("#check_param_table", DataTable).cursor_row]
        await pilot.press("space")
        await settle(pilot, 3)
        count = str(panel.query_one("#check_fields_count").render())
        lines = fields_lines(app, panel)
        assert await _focus_by_tab(app, pilot, "check_write_button")
        await pilot.press("enter")
        await settle(pilot, 4)
        written = sorted((app.workarea / "patches").glob("*.chk.json"))
        return name, panel._param_rows[name][0], count, lines, written

    name, address, count, lines, written = run(tmp_path, (118, 54), body, cover_image=True)
    assert count.startswith("1 field "), count
    assert [(m, a) for m, a, _n in lines] == [("◆", f"0x{address:08X}")], lines
    assert len(written) == 1, written
    doc = json.loads(written[0].read_text(encoding="utf-8"))
    assert [int(e["address"], 16) for e in doc["entries"]] == [address]


def test_at_b97_21_six_shared_address_fields_and_the_written_file(tmp_path: Path) -> None:
    """AT-B97-21 (HLR-145): the engineer includes the six parameters at
    ``0x13A00`` and one memory row typed into its labelled inputs, clicks the
    Fields, JSON and Addendum chips and Write: the Fields card lists the seven
    included fields with six distinct names, the JSON tab holds the written
    file's addresses, and the Addendum tab shows its preview.

    RED on main: no Fields tab; the JSON preview is not a JSON document.
    """

    async def body(app, pilot, panel):
        await pilot.press("equals_sign")
        await settle(pilot, 4)
        filt = panel.query_one("#check_param_filter", Input)
        for name in SIX_13A00:
            filt.value = name
            await settle(pilot, 2)
            exact = [i for i, n in enumerate(panel._visible_params) if n == name]
            panel.query_one("#check_param_table", DataTable).move_cursor(row=exact[0])
            await pilot.click("#check_param_include_button")
            await settle(pilot, 2)
        filt.value = ""
        await settle(pilot, 2)
        await _add_memory_row(panel, pilot, "0x13A01", "probe", "1")
        await click_if(pilot, panel, "#check_tab_fields")
        lines = fields_lines(app, panel)
        await click_if(pilot, panel, "#check_tab_json")
        doc = json_tab(panel)
        await click_if(pilot, panel, "#check_tab_addendum")
        addendum = is_displayed(panel.query_one("#check_addendum_preview"))
        await pilot.click("#check_write_button")
        await settle(pilot, 4)
        written = sorted((app.workarea / "patches").glob("*.chk.json"))
        return lines, doc, addendum, written

    lines, doc, addendum, written = run(tmp_path, (118, 54), body, cover_image=True)
    assert doc is not None, "the JSON tab must hold a JSON document"
    assert len(lines) == 7, lines
    assert [m for m, _a, _n in lines] == ["◆"] * 6 + ["▪"]
    assert len({n for _m, _a, n in lines[:6]}) == 6
    assert addendum
    assert len(written) == 1
    on_disk = [e["address"] for e in json.loads(written[0].read_text(encoding="utf-8"))["entries"]]
    assert [int(e["address"], 16) for e in doc["entries"]] == [int(a, 16) for a in on_disk]
    assert len(on_disk) == 7


# --------------------------------------------------------------------------- #
# Inc-3 gate fold — the full-name line (F1, L2) and the 120..133 band (LED .13)
# --------------------------------------------------------------------------- #


def _full_name_reading(app, panel) -> tuple:
    """(painted full-name line stripped, its content width)."""
    line = need(panel, "#check_full_name_line")
    return painted_rows(app, line)[0].strip(), line.content_region.width


def test_tc_b97_10_full_name_line_keeps_address_and_name_tail(tmp_path: Path) -> None:
    """TC-B97-10 (LLR-145.3, full-name line; code-reviewer F1, ux-reviewer L2):
    with a 173-cell name highlighted, the line paints the address whole first,
    then the row's full ``Fmt · Unit``, then the name clipped to the width left
    by the LLR-145.3 rule — first segment, exactly one ``…``, the name's tail
    as the line's last cells — filling the line; after a resize to 220x60 the
    line is recomposed to the new width (PC-19), not left at the 118 text.

    Why: a CSS ellipsis at the line's end cut the address and the tail — the
    two parts that tell twins apart. RED on the pre-fold tree: the line starts
    with the name. Mutations: name before the address; a head-keeping clip;
    the line not recomposed by ``_apply_layout``.
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        table.move_cursor(row=panel._visible_params.index(LONG_NAME))
        await settle(pilot, 2)
        at_118 = _full_name_reading(app, panel)
        await pilot.resize_terminal(220, 60)
        await settle(pilot, 6)
        at_220 = _full_name_reading(app, panel)
        address, _size, fmt_unit = panel._param_rows[LONG_NAME]
        return at_118, at_220, f"0x{address:08X}", fmt_unit.rstrip()

    at_118, at_220, address, fmt_unit = run(tmp_path, (118, 54), body, a2l=long_name_a2l(tmp_path))
    for text, width in (at_118, at_220):
        assert text.startswith(f"{address}  {fmt_unit}  "), (text, address, fmt_unit)
        name_part = text[len(f"{address}  {fmt_unit}  "):]
        assert name_part.startswith("ASAM…") and name_part.count("…") == 1, name_part
        assert text.endswith(LONG_NAME[-(len(name_part) - len("ASAM…")):]), text
        assert text.endswith("_TAIL_MARK"), text
        assert len(text) == width, (len(text), width, text)
    assert at_220[1] > at_118[1], "the 220x60 line is wider and was recomposed"


@pytest.mark.parametrize("size", [(119, 54), (120, 54), (126, 54), (133, 54), (134, 54)])
def test_tc_b97_10_parameter_floor_at_the_wide_breakpoint(tmp_path: Path, size) -> None:
    """TC-B97-10 (LLR-145.3 as amended by LED-2026-10-19-batch-97.13, the
    120..133 band): the Parameter column keeps >= 42 cells at 119 and from 134,
    and >= 28 in the degraded band 120..133 where the wide-regime rail takes 16
    more cells; across the band the 75 painted ledger rows stay pairwise
    distinct (the address tells the clipped twins apart) and the full-name line
    of the highlighted 47-cell row holds its address and ends with its tail.

    Replaces the strict xfail of the first Inc-3 run (operator decision at the
    gate, 2026-10-21). RED by mutation: the Address cell painted blank (twins
    collide inside the band).
    """

    async def body(app, pilot, panel):
        table = panel.query_one("#check_param_table", DataTable)
        painted = await painted_table(app, pilot, table)
        table.move_cursor(row=panel._visible_params.index(LONGEST_NAME))
        await settle(pilot, 2)
        line, _w = _full_name_reading(app, panel)
        return table.ordered_columns[1].width, painted, line, panel._param_rows[LONGEST_NAME][0]

    width, painted, line, address = run(tmp_path, size, body)
    floor = 28 if 120 <= size[0] <= 133 else 42
    assert width >= floor, (size, width)
    assert len(painted) == 75 and len(set(painted.values())) == 75, (size, len(set(painted.values())))
    assert line.startswith(f"0x{address:08X}") and line.endswith(LONGEST_NAME[-16:]), (size, line)
