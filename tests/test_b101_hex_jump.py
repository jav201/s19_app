"""batch-101 Inc 10a - hex navigation (tester H of E4).

Written by an independent tester from the approved design only:
``inc-10/01-requirements.md`` (rows and thresholds), ``02-test-cases.md`` (the
cases with the wait rule and the window-switch rule), ``codewire/graph-inc10.md``
(the examples, used as oracles) and ``E3-rulings.md``. No line of the Inc 10a
implementation was read to decide what to assert. The nodes and clauses marked
"E5" were written by the E5 corrective pass, which had read it
(``inc-10/E5-corrective-notes.md``).

Group H: where a jump lands and what the ``> `` marker does.

  - R-TUI-018.1 / .2 / .3 / .4 - the target row is the second row of the view
    (the first row when it is the first view row), scrolled to the top-left,
    in the main, A2L and MAC views; a target outside the image lands on the
    snapped present row.
  - R-TUI-040.4 / .8 / .11 / .12 - the go-to places its row like any jump, a
    failed go-to leaves the rows and removes the marker, every other jump
    removes the marker.
  - R-TUI-007.3 / .5 / .8 - ``.`` pages from the shown window and counts the
    rows added for MAC records.

Oracles are what the app painted: the plain text of ``#hex_view``,
``#alt_hex_view`` and ``#mac_hex_view`` (a hex row is a line that starts with
``> `` or two spaces and ``0x``), the scroll offsets and regions of their
scroll containers, and the status lines the app wrote (read with
``StatusLog.since(mark)``). The marker address fields are read only where the
requirement states "the marker address is cleared" (R-TUI-040.12). Every wait
polls a sign the app produced through ``tests/support/timing.py::wait_until``;
a state that only the Inc 10a behaviour reaches is waited for with the short
``FIX_WAIT`` so that a missing behaviour fails with the painted state in the
message instead of after the shared 60 s bound. No bare ``pilot.pause()`` is
counted as a wait, and every negative assertion follows a positive wait (the
action's own status line) in the same test.

Windows are switched with the rail keys only (``1``, ``2``, ``3``, ``4``).
No test drives the issue jump (withdrawn, Inc 12 D-2). ``LOCALAPPDATA`` is
isolated by ``tests/conftest.py``; no case touches the OS clipboard.
"""
from __future__ import annotations

import re
import sys
from bisect import bisect_left
from pathlib import Path

import pytest
from textual.containers import ScrollableContainer
from textual.widgets import DataTable, Input, ListView, Static, TextArea

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from tests.support import b100_projects as projects  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402
from tests.test_tui_directionb import _double_click_region_row  # noqa: E402

SEED = 20260001
SIZE_MB = 1.0
SIZE = (120, 56)  # measured screen 118 x 54, the guide's regime

#: Ceiling of a wait for a state only the Inc 10a behaviour reaches.
FIX_WAIT = 10.0

#: A view: rail key, hex Static, scroll container, go-to input id, search input
#: id, marker address field of the app. Unpacked into plain names before any
#: query (the address census wants literal or plain-name selectors).
MAIN = ("1", "#hex_view", "#hex_scroll", "goto_input", "search_input", "_goto_focus_address")
ALT = ("2", "#alt_hex_view", "#alt_hex_scroll", "alt_goto_input", "alt_search_input", "_alt_goto_focus_address")
MAC = ("3", "#mac_hex_view", "#mac_hex_scroll", "mac_goto_input", "mac_search_input", "_mac_goto_focus_address")
VIEWS = {"main": MAIN, "a2l": ALT, "mac": MAC}

MISS = "Address 0xFFFFFFF0 not in loaded file."
LAST_ROW = 0x00C00FF0  # last present row of case 08 (config region ends 0x00C00FFF)


# ---------------------------------------------------------------------------
# Fixtures: images, the MAC below the image, case 08
# ---------------------------------------------------------------------------


def _s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_three(path: Path) -> Path:
    """Fixture three: ranges 0x8000 (00..07), 0x8010 (eight FF), 0x8020 (20..27)."""
    lines = [
        "S0030000FC",
        _s1(0x8000, bytes(range(8))),
        _s1(0x8010, b"\xff" * 8),
        _s1(0x8020, bytes(range(0x20, 0x28))),
        "S9030000FC",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def write_mac_below(path: Path) -> Path:
    """One valid MAC record at 0x00001000, outside fixture three."""
    path.write_text("LOW_SYMBOL=0x00001000\n", encoding="utf-8")
    return path


def write_rows(path: Path, count: int) -> Path:
    """``count`` contiguous 16-byte rows from 0x8000 (row n at 0x8000 + 16 n)."""
    lines = ["S0030000FC"]
    for n in range(count):
        lines.append(_s1(0x8000 + 16 * n, bytes((n + i) & 0xFF for i in range(16))))
    lines.append("S9030000FC")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def row_at(n: int) -> int:
    """Address of row ``n`` of ``write_rows``."""
    return 0x8000 + 16 * n


@pytest.fixture(scope="module")
def case08(tmp_path_factory) -> Path:
    """Case 08: seed 20260001, 1.0 MB (26 546 present rows)."""
    folder = tmp_path_factory.mktemp("case08")
    gen.generate(folder, SEED, SIZE_MB)
    return folder


def drive(tmp_path: Path, scenario, size: tuple = SIZE):
    base = tmp_path / "app"
    base.mkdir(parents=True, exist_ok=True)
    return projects.run_app(base, scenario, size=size)


# ---------------------------------------------------------------------------
# What the app painted
# ---------------------------------------------------------------------------


def plain(widget) -> str:
    content = getattr(widget, "content", None)
    if content is None:
        content = widget.renderable
    return str(content)


def hex_rows(app, hex_id: str) -> list:
    """The hex row lines of one view, in painted order."""
    lines = plain(app.query_one(hex_id, Static)).splitlines()
    return [ln for ln in lines if ln.startswith(("> ", "  0x"))]


def notices(app, hex_id: str) -> list:
    lines = plain(app.query_one(hex_id, Static)).splitlines()
    return [ln for ln in lines if ln.startswith("...")]


def marked_rows(app, hex_id: str) -> list:
    return [ln for ln in hex_rows(app, hex_id) if ln.startswith("> ")]


def addr_of(row: str) -> int:
    return int(row[2:12], 16)


def addrs(app, hex_id: str, count: int = 3) -> list:
    return [addr_of(r) for r in hex_rows(app, hex_id)[:count]]


def line_index(st, address: int):
    """Index, in the Static's text, of the line of the hex row at ``address``."""
    tag = f"0x{address:08X}"
    for index, line in enumerate(plain(st).splitlines()):
        if line[2:12] == tag:
            return index
    return None


def line_inside_pane(sc, st, address: int) -> bool:
    """The row's line lies inside the scroll container's region (no scroll)."""
    index = line_index(st, address)
    if index is None or sc.scroll_y != 0:
        return False
    y = st.region.y + index
    return sc.region.y <= y < sc.region.y + sc.region.height


def fmt(values) -> str:
    return "[" + ", ".join("None" if v is None else f"0x{v:08X}" for v in values) + "]"


# ---------------------------------------------------------------------------
# Waits and drives (keys, buttons, tables; nothing is called on the app)
# ---------------------------------------------------------------------------


async def wait_rows(pilot, app, view, expected: list, what: str, *, timeout: float = FIX_WAIT) -> None:
    """Wait until the first ``len(expected)`` painted rows of ``view`` have
    exactly these addresses; the failure shows what was painted."""
    _key, hex_id, _scroll, _goto, _search, _field = view
    count = len(expected)
    await wait_until(
        pilot,
        lambda: addrs(app, hex_id, count) == expected,
        lambda: f"{what}: first rows {fmt(addrs(app, hex_id, count))}, expected {fmt(expected)}",
        timeout=timeout,
    )


async def wait_no_marker(pilot, app, view, what: str) -> None:
    _key, hex_id, _scroll, _goto, _search, _field = view
    await wait_until(
        pilot,
        lambda: not marked_rows(app, hex_id),
        lambda: f"{what}: {len(marked_rows(app, hex_id))} marked line(s) {marked_rows(app, hex_id)[:1]!r}",
        timeout=FIX_WAIT,
    )


def _status_match(log, mark: int, text):
    """The first status line since ``mark`` equal to ``text`` (a string) or
    fully matching it (a compiled pattern); ``None`` when there is none."""
    for message in log.since(mark):
        if isinstance(text, str):
            if message == text:
                return message
        elif text.fullmatch(message):
            return message
    return None


async def wait_status(pilot, log, mark: int, text) -> str:
    await wait_until(
        pilot,
        lambda: _status_match(log, mark, text) is not None,
        lambda: f"status {text!r} not written; since the trigger: {log.since(mark)!r}",
    )
    return _status_match(log, mark, text)


async def show(pilot, app, view) -> None:
    """Show the window of ``view`` with its rail key and wait until it is laid
    out and has painted hex rows."""
    key, hex_id, scroll_id, _goto, _search, _field = view
    await pilot.press(key)
    await wait_until(
        pilot,
        lambda: app.query_one(scroll_id, ScrollableContainer).region.height > 0,
        f"the window of key {key} was not laid out",
    )
    await wait_until(pilot, lambda: bool(hex_rows(app, hex_id)), f"no hex rows painted in {hex_id}")
    # Where the focus lands after a rail key is group F's subject. A text box
    # focused in a hidden window would swallow the next 'g' or '/', so clear it.
    if isinstance(app.default_screen.focused, Input):
        app.default_screen.set_focus(None)
        await wait_until(pilot, lambda: app.default_screen.focused is None, "the stray text-box focus was not cleared")


async def focus_input(pilot, app, key: str, input_id: str) -> None:
    await pilot.press(key)
    await wait_until(
        pilot,
        lambda: getattr(app.default_screen.focused, "id", None) == input_id,
        lambda: f"key {key!r} did not focus #{input_id}; focused {getattr(app.default_screen.focused, 'id', None)!r}",
    )


async def type_into_focused(pilot, app, input_id: str, text: str) -> None:
    """Type ``text`` into the focused box (the focus selects its old text; an
    empty ``text`` deletes it) and wait until the box holds exactly it."""
    if text:
        await pilot.press(*list(text))
    else:
        await pilot.press("backspace")
    await wait_until(
        pilot,
        lambda: app.query_one(f"#{input_id}", Input).value == text,
        lambda: f"#{input_id} holds {app.query_one(f'#{input_id}', Input).value!r}, expected {text!r}",
    )


async def goto(pilot, app, log, view, text: str, status: str) -> int:
    """``g``, the text, Tab, Enter; wait for ``status``. Returns the log mark."""
    _key, _hex, _scroll, goto_id, _search, _field = view
    mark = len(log.messages)
    await focus_input(pilot, app, "g", goto_id)
    await type_into_focused(pilot, app, goto_id, text)
    await pilot.press("tab", "enter")
    await wait_status(pilot, log, mark, status)
    return mark


def hit(address: int) -> str:
    return f"Goto 0x{address:08X}"


async def search(pilot, app, log, view, text, status) -> int:
    """``/``, the text (``None`` keeps the box), Tab, Enter; wait for ``status``."""
    _key, _hex, _scroll, _goto, search_id, _field = view
    mark = len(log.messages)
    await focus_input(pilot, app, "slash", search_id)
    if text is None:
        assert app.query_one(f"#{search_id}", Input).value, "the box must still hold the earlier text"
    else:
        await type_into_focused(pilot, app, search_id, text)
    await pilot.press("tab", "enter")
    await wait_status(pilot, log, mark, status)
    return mark


async def tag_find(pilot, app, log, name: str) -> int:
    """Type ``name`` in the A2L tag-find box, Tab to Find next, Enter."""
    mark = len(log.messages)
    app.query_one("#a2l_tag_find_input", Input).focus()
    await wait_until(
        pilot,
        lambda: getattr(app.default_screen.focused, "id", None) == "a2l_tag_find_input",
        "the tag-find box did not take the focus",
    )
    await type_into_focused(pilot, app, "a2l_tag_find_input", name)
    await pilot.press("tab")
    await wait_until(
        pilot,
        lambda: getattr(app.default_screen.focused, "id", None) == "a2l_tag_find_next",
        "Tab did not reach the Find next button",
    )
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: any(m.startswith(f"Tag find: {name}") for m in log.since(mark)),
        lambda: f"no 'Tag find: {name}' line; since the trigger: {log.since(mark)!r}",
    )
    return mark


async def scroll_away(pilot, app, scroll_id: str, *, need_x: bool) -> tuple:
    """Scroll one hex pane to x 10, y 40 (as far as its content allows; the A2L
    and MAC panes have no horizontal range, finding F-2); wait for it."""
    sc = app.query_one(scroll_id, ScrollableContainer)
    sc.scroll_to(x=10, y=40, animate=False)
    await wait_until(
        pilot,
        lambda: sc.scroll_y > 0 and (sc.scroll_x > 0 or not need_x),
        lambda: f"{scroll_id} did not scroll away: ({sc.scroll_x}, {sc.scroll_y})",
    )
    return (sc.scroll_x, sc.scroll_y)


async def load_case(pilot, app, case08: Path, *, a2l: str = "", mac: str = "") -> None:
    """Load case 08's image, then an A2L and a MAC file when named."""
    image = case08 / "firmware.s19"
    app.load_selected_file(image)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == image.name,
        "the image load did not finish",
    )
    await settle_workers(pilot)
    await wait_until(pilot, lambda: bool(hex_rows(app, "#hex_view")), "no hex rows after the image load")
    if a2l:
        app.load_a2l_from_path(case08 / a2l)
        await wait_until(pilot, lambda: app.current_a2l_data is not None, "the A2L load did not finish")
        await settle_workers(pilot)
    if mac:
        app.load_selected_file(case08 / mac)
        await wait_until(
            pilot,
            lambda: app.current_file is not None and app.current_file.mac_path is not None,
            "the MAC load did not finish",
        )
        await settle_workers(pilot)


async def load_three(pilot, app, tmp_path: Path, *, mac: bool) -> None:
    image = write_three(tmp_path / "three.s19")
    app.load_selected_file(image)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == image.name,
        "the image load did not finish",
    )
    await settle_workers(pilot)
    if mac:
        app.load_selected_file(write_mac_below(tmp_path / "below.mac"))
        await wait_until(
            pilot,
            lambda: app.current_file is not None and app.current_file.mac_path is not None,
            "the MAC load did not finish",
        )
        await settle_workers(pilot)


def loads_for(view_name: str) -> dict:
    """The artifacts a case loads for one view (image always)."""
    return {"main": {}, "a2l": {"a2l": "firmware.a2l"}, "mac": {"mac": "firmware.mac"}}[view_name]


async def start(pilot, app, case08: Path, view_name: str) -> tuple:
    """Load what ``view_name`` needs from case 08 and show its window."""
    view = VIEWS[view_name]
    await load_case(pilot, app, case08, **loads_for(view_name))
    await show(pilot, app, view)
    return view


def a2l_address(a2l_text: str, name: str) -> int:
    """The address an A2L file declares for ``name`` (read with a regular
    expression, not with the app's parser)."""
    found = re.search(
        r"/begin (?:MEASUREMENT|CHARACTERISTIC) " + re.escape(name)
        + r" .*?(?:ECU_ADDRESS|VALUE|VAL_BLK|ASCII|CURVE|MAP)\s+(0x[0-9A-Fa-f]+)",
        a2l_text,
        re.S,
    )
    assert found, f"{name} not declared in the A2L"
    return int(found.group(1), 16)


# ---------------------------------------------------------------------------
# R-TUI-018.1 - the target row is the second row
# ---------------------------------------------------------------------------


def test_r_tui_018_1_1_main_goto_target_is_second_row(tmp_path, case08):
    """R-TUI-018.1/1: a main go-to shows its target as the second row."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        await goto(pilot, app, log, view, "0x00000960", hit(0x960))
        await wait_rows(pilot, app, view, [0x950, 0x960], "main go-to 0x00000960")
        shown = notices(app, "#hex_view")
        assert any(n.startswith("... showing from 0x00000950") for n in shown), shown

    drive(tmp_path, scenario)


def test_r_tui_018_1_2_main_find_next_hit_is_second_row(tmp_path, case08):
    """R-TUI-018.1/2: a main Find Next hit is the second row."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        await search(pilot, app, log, view, "BUILD_ID", "Found at 0x00C00050")
        await wait_rows(pilot, app, view, [0x00C00040, 0x00C00050], "main Find Next BUILD_ID")

    drive(tmp_path, scenario)


def test_r_tui_018_1_3_section_jump_shows_range_start_second(tmp_path, case08):
    """R-TUI-018.1/3: a section jump shows the range start as the second row."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        sections = app.query_one("#sections_list", ListView)
        await wait_until(pilot, lambda: len(sections.children) >= 2, "the Data Sections list is empty")
        assert sections.children[1].data[0] == 0x00040000, "the second section must start at 0x00040000"
        sections.focus()
        await wait_until(pilot, lambda: app.default_screen.focused is sections, "the section list did not take the focus")
        sections.index = 1
        await wait_until(pilot, lambda: sections.index == 1, "the section cursor did not move")
        shown_before = addrs(app, "#hex_view", 1)
        await pilot.press("enter")
        # The positive sign of the jump: the window moved (no section status exists).
        await wait_until(pilot, lambda: addrs(app, "#hex_view", 1) != shown_before, "the section jump did not move the window")
        bases = app.current_file.row_bases
        above = bases[bisect_left(bases, 0x00040000) - 1]
        await wait_rows(pilot, app, view, [above, 0x00040000], "section jump to 0x00040000")

    drive(tmp_path, scenario)


def test_r_tui_018_1_4_map_open_in_hex_snapped_row_second(tmp_path, case08):
    """R-TUI-018.1/4: a Memory Map open-in-hex shows the snapped target row second."""
    from s19_app.tui.screens_directionb import MemoryMapPanel

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        await pilot.press("4")
        panel = app.query_one("#memory_map_panel", MemoryMapPanel)
        await wait_until(pilot, lambda: len(panel._live_region_rows()) >= 2, "the map lists fewer than two regions")
        chosen = panel._live_region_rows()[1].region_start
        bases = app.current_file.row_bases
        assert chosen > bases[0], "the chosen region must not start at the first view row"
        await _double_click_region_row(pilot, app, lambda r: r.region_start == chosen)
        await wait_until(
            pilot,
            lambda: app.query_one("#hex_scroll", ScrollableContainer).region.height > 0,
            "the Workspace was not shown by the open-in-hex",
        )
        index = bisect_left(bases, chosen - chosen % 16)
        await wait_rows(pilot, app, view, [bases[index - 1], bases[index]], f"open-in-hex of 0x{chosen:08X}")

    drive(tmp_path, scenario)


def test_r_tui_018_1_6_a2l_goto_target_is_second_row(tmp_path, case08):
    """R-TUI-018.1/6: an A2L go-to shows its target second (base: row 65)."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "a2l")
        await goto(pilot, app, log, view, "0x00000960", hit(0x960))
        await wait_rows(pilot, app, view, [0x950, 0x960], "A2L go-to 0x00000960")

    drive(tmp_path, scenario)


def test_r_tui_018_1_7_a2l_search_hit_is_second_row(tmp_path, case08):
    """R-TUI-018.1/7: an A2L search hit is the second row."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "a2l")
        await search(pilot, app, log, view, "BUILD_ID", "Found at 0x00C00050")
        await wait_rows(pilot, app, view, [0x00C00040, 0x00C00050], "A2L search BUILD_ID")

    drive(tmp_path, scenario)


def test_r_tui_018_1_8_a2l_tag_find_shows_tag_row_second(tmp_path, case08):
    """R-TUI-018.1/8: an A2L tag find shows the tag's row second."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "a2l")
        target = a2l_address((case08 / "firmware.a2l").read_text(encoding="utf-8"), "VALUE_0200")
        row = target - target % 16
        bases = app.current_file.row_bases
        assert row in bases, "the tag's row must be a present row"
        above = bases[bisect_left(bases, row) - 1]
        await tag_find(pilot, app, log, "VALUE_0200")
        await wait_rows(pilot, app, view, [above, row], "A2L tag find VALUE_0200")

    drive(tmp_path, scenario)


def test_r_tui_018_1_9_mac_goto_target_is_second_row(tmp_path, case08):
    """R-TUI-018.1/9: a MAC go-to shows its target second."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "mac")
        await goto(pilot, app, log, view, "0x00000960", hit(0x960))
        await wait_rows(pilot, app, view, [0x950, 0x960], "MAC go-to 0x00000960")

    drive(tmp_path, scenario)


def test_r_tui_018_1_10_mac_search_hit_is_second_row(tmp_path, case08):
    """R-TUI-018.1/10: a MAC search hit is the second row."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "mac")
        await search(pilot, app, log, view, "BUILD_ID", "Found at 0x00C00050")
        await wait_rows(pilot, app, view, [0x00C00040, 0x00C00050], "MAC search BUILD_ID")

    drive(tmp_path, scenario)


def test_r_tui_018_1_11_jump_to_last_present_row_still_second(tmp_path, case08):
    """R-TUI-018.1/11: a jump to the last present row shows it second; 2 rows."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        bases = app.current_file.row_bases
        assert bases[-1] == LAST_ROW and bases[-2] == LAST_ROW - 0x10
        await goto(pilot, app, log, view, f"0x{LAST_ROW:08X}", hit(LAST_ROW))
        await wait_rows(pilot, app, view, [LAST_ROW - 0x10, LAST_ROW], "jump to the last present row")
        assert len(hex_rows(app, "#hex_view")) == 2, hex_rows(app, "#hex_view")
        assert not any("window limited" in n for n in notices(app, "#hex_view")), notices(app, "#hex_view")

    drive(tmp_path, scenario)


def test_r_tui_018_1_12_mac_row_below_image_counts_as_row_above(tmp_path):
    """R-TUI-018.1/12: a MAC record below the image is a row above the target
    in each of the three views (base: 0x00008020 third)."""

    async def scenario(app, pilot, log):
        await load_three(pilot, app, tmp_path, mac=True)
        for view_name in ("main", "a2l", "mac"):
            view = VIEWS[view_name]
            await show(pilot, app, view)
            # The MAC row is the first view row before the jump (so it can count).
            await wait_rows(pilot, app, view, [0x1000, 0x8000, 0x8010], f"{view_name} rows before the jump")
            await goto(pilot, app, log, view, "0x00008020", hit(0x8020))
            await wait_rows(pilot, app, view, [0x8010, 0x8020], f"{view_name} go-to 0x00008020")

    drive(tmp_path, scenario)


@pytest.mark.parametrize("view_name", ["main", "a2l", "mac"])
def test_r_tui_018_1_13_target_row_inside_pane_at_80x24(tmp_path, case08, view_name):
    """R-TUI-018.1/13: at 80 x 24 the target row's line lies inside the region of
    the view's scroll container. A pane shorter than 4 lines cannot hold the
    second row below its notice lines: the arm skips by name (finding F-1)."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l="firmware.a2l", mac="firmware.mac")
        view = VIEWS[view_name]
        _key, hex_id, scroll_id, _goto, _search, _field = view
        await show(pilot, app, view)
        sc = app.query_one(scroll_id, ScrollableContainer)
        height = sc.region.height
        if height < 4:
            pytest.skip(f"the {view_name} pane is {height} line(s) high at 80 x 24: no second row can lie inside it")
        await goto(pilot, app, log, view, "0x00000960", hit(0x960))
        await wait_rows(pilot, app, view, [0x950, 0x960], f"{view_name} go-to at 80 x 24")
        st = app.query_one(hex_id, Static)

        await wait_until(
            pilot,
            lambda: line_inside_pane(sc, st, 0x960),
            lambda: f"{view_name}: target line not inside the pane; scroll_y {sc.scroll_y}, pane {sc.region}, content {st.region}",
            timeout=FIX_WAIT,
        )

    drive(tmp_path, scenario, size=(80, 24))


def test_r_tui_018_1_13b_main_target_row_inside_pane_at_100x30(tmp_path, case08):
    """R-TUI-018.1/13 (extension, finding F-1): the main arm that 80 x 24 cannot
    hold, at the smallest measured size whose Workspace pane has 7 lines."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        sc = app.query_one("#hex_scroll", ScrollableContainer)
        assert sc.region.height >= 4, f"the pane is {sc.region.height} line(s) high at 100 x 30"
        await goto(pilot, app, log, view, "0x00000960", hit(0x960))
        await wait_rows(pilot, app, view, [0x950, 0x960], "main go-to at 100 x 30")
        st = app.query_one("#hex_view", Static)

        await wait_until(
            pilot,
            lambda: line_inside_pane(sc, st, 0x960),
            lambda: f"target line not inside the pane; scroll_y {sc.scroll_y}, pane {sc.region}, content {st.region}",
            timeout=FIX_WAIT,
        )

    drive(tmp_path, scenario, size=(100, 30))


# ---------------------------------------------------------------------------
# R-TUI-018.2 - the jump scrolls to the first line and the left edge
# ---------------------------------------------------------------------------


async def _scroll_reset_case(pilot, app, log, case08, view_name) -> None:
    view = await start(pilot, app, case08, view_name)
    _key, _hex, scroll_id, _goto, _search, _field = view
    sc = app.query_one(scroll_id, ScrollableContainer)
    away = await scroll_away(pilot, app, scroll_id, need_x=(view_name == "main"))
    await goto(pilot, app, log, view, "0x00000140", hit(0x140))
    await wait_until(
        pilot,
        lambda: sc.scroll_x == 0 and sc.scroll_y == 0,
        lambda: f"{view_name}: scroll is ({sc.scroll_x}, {sc.scroll_y}) after the jump, was {away}",
        timeout=FIX_WAIT,
    )


def test_r_tui_018_2_1_main_jump_resets_both_axes(tmp_path, case08):
    """R-TUI-018.2/1: a main jump resets both scroll axes (base: stays)."""

    async def scenario(app, pilot, log):
        await _scroll_reset_case(pilot, app, log, case08, "main")

    drive(tmp_path, scenario)


def test_r_tui_018_2_2_a2l_jump_resets_both_axes(tmp_path, case08):
    """R-TUI-018.2/2: the same for the A2L hex view."""

    async def scenario(app, pilot, log):
        await _scroll_reset_case(pilot, app, log, case08, "a2l")

    drive(tmp_path, scenario)


def test_r_tui_018_2_3_mac_jump_resets_both_axes(tmp_path, case08):
    """R-TUI-018.2/3: the same for the MAC hex view."""

    async def scenario(app, pilot, log):
        await _scroll_reset_case(pilot, app, log, case08, "mac")

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-018.3 - a target outside the image lands on the snapped present row
# ---------------------------------------------------------------------------


def test_r_tui_018_3_2_a2l_tag_outside_image_lands_on_snapped_row(tmp_path, case08):
    """R-TUI-018.3/2: an A2L tag find of a tag outside the image lands on the
    snapped row: the last present row, 0x00D00000 being past the image."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l="firmware_issues.a2l")
        view = ALT
        await show(pilot, app, view)
        await wait_until(
            pilot,
            lambda: any(t.get("name") == "OUT_OF_RANGE_1" for t in app._a2l_filtered_tags),
            "firmware_issues.a2l tags are not listed",
        )
        tag = next(t for t in app._a2l_filtered_tags if t.get("name") == "OUT_OF_RANGE_1")
        assert tag["address"] == 0x00D00000 and tag["address"] > LAST_ROW + 15
        await tag_find(pilot, app, log, "OUT_OF_RANGE_1")
        await wait_rows(pilot, app, view, [LAST_ROW - 0x10, LAST_ROW], "A2L tag find OUT_OF_RANGE_1")

    drive(tmp_path, scenario)


def test_r_tui_018_3_3_mac_record_outside_image_lands_on_snapped_row(tmp_path, case08):
    """R-TUI-018.3/3: a MAC record jump to an address outside the image lands on
    the last present row (base: centred on the record's own row)."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, mac="firmware_issues.mac")
        view = MAC
        await show(pilot, app, view)
        table = app.query_one("#mac_records_list", DataTable)

        def cells(index: int) -> list:
            return [str(v) for v in table.get_row_at(index)]

        def has_target() -> bool:
            return any("0x00FF0000" in cells(i) for i in range(table.row_count))

        for _ in range(3):
            if has_target():
                break
            before = cells(0)
            await pilot.press("plus")
            await wait_until(pilot, lambda: cells(0) != before, "the MAC table did not page")
        assert has_target(), "no MAC row of 0x00FF0000 within the first three pages"
        index = next(i for i in range(table.row_count) if "0x00FF0000" in cells(i))
        assert "no" in cells(index)[2:4], cells(index)  # not in A2L / not in memory
        mark = len(log.messages)
        table.focus()
        await wait_until(pilot, lambda: app.default_screen.focused is table, "the MAC table did not take the focus")
        table.move_cursor(row=index)
        await wait_until(pilot, lambda: table.cursor_row == index, "the MAC cursor did not move")
        await pilot.press("enter")
        await wait_status(pilot, log, mark, "MAC tag at 0x00FF0000")
        await wait_rows(pilot, app, view, [LAST_ROW - 0x10, LAST_ROW], "MAC record jump to 0x00FF0000")

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-018.4 - a jump to the first view row shows it first
# ---------------------------------------------------------------------------


def test_r_tui_018_4_1_first_view_row_shown_first_and_miss_keeps_it(tmp_path, case08):
    """R-TUI-018.4/1: a go-to of 0x00000000 shows it as the first row with no
    'showing from' line in each view, and a later miss keeps the first row."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l="firmware.a2l", mac="firmware.mac")
        for view_name in ("main", "a2l", "mac"):
            view = VIEWS[view_name]
            _key, hex_id, _scroll, _goto, _search, _field = view
            await show(pilot, app, view)
            await goto(pilot, app, log, view, "0x00000000", hit(0))
            await wait_rows(pilot, app, view, [0x0], f"{view_name} go-to 0x00000000")
            assert not any(n.startswith("... showing from") for n in notices(app, hex_id)), notices(app, hex_id)
            await goto(pilot, app, log, view, "0xFFFFFFF0", MISS)
            assert addrs(app, hex_id, 1) == [0x0], f"{view_name}: first row {fmt(addrs(app, hex_id, 1))} after the miss"

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-040.4 - the go-to places its row like any jump
# ---------------------------------------------------------------------------


async def _goto_inside_row(pilot, app, log, case08, view_name) -> None:
    view = await start(pilot, app, case08, view_name)
    _key, hex_id, _scroll, _goto, _search, _field = view
    await goto(pilot, app, log, view, "0x00000965", hit(0x965))
    await wait_rows(pilot, app, view, [0x950, 0x960], f"{view_name} go-to 0x00000965")
    assert hex_rows(app, hex_id)[1].startswith("> "), hex_rows(app, hex_id)[1]


def test_r_tui_040_4_1_main_goto_target_row_second_and_marked(tmp_path, case08):
    """R-TUI-040.4/1: the main go-to target row is second, marked '> '."""

    async def scenario(app, pilot, log):
        await _goto_inside_row(pilot, app, log, case08, "main")

    drive(tmp_path, scenario)


def test_r_tui_040_4_2_a2l_goto_target_row_second_and_marked(tmp_path, case08):
    """R-TUI-040.4/2: the A2L go-to likewise."""

    async def scenario(app, pilot, log):
        await _goto_inside_row(pilot, app, log, case08, "a2l")

    drive(tmp_path, scenario)


def test_r_tui_040_4_3_mac_goto_target_row_second_and_marked(tmp_path, case08):
    """R-TUI-040.4/3: the MAC go-to likewise."""

    async def scenario(app, pilot, log):
        await _goto_inside_row(pilot, app, log, case08, "mac")

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-040.8 - a go-to miss leaves the rows unchanged
# ---------------------------------------------------------------------------


async def _miss_leaves_rows(pilot, app, log, case08, view_name) -> None:
    view = await start(pilot, app, case08, view_name)
    _key, hex_id, _scroll, _goto, _search, _field = view
    await goto(pilot, app, log, view, "0x00000050", hit(0x50))
    await wait_until(pilot, lambda: len(marked_rows(app, hex_id)) == 1, "the go-to painted no marker")
    before = [r[2:] for r in hex_rows(app, hex_id)]
    await goto(pilot, app, log, view, "0xFFFFFFF0", MISS)
    after = [r[2:] for r in hex_rows(app, hex_id)]
    assert after == before, f"{view_name}: the miss changed the rows ({len(before)} before, {len(after)} after)"


def test_r_tui_040_8_1_main_miss_leaves_rows(tmp_path, case08):
    """R-TUI-040.8/1: a main go-to miss leaves the rows unchanged (a standing
    guard on base: it fails if the miss re-renders from another window)."""

    async def scenario(app, pilot, log):
        await _miss_leaves_rows(pilot, app, log, case08, "main")

    drive(tmp_path, scenario)


def test_r_tui_040_8_2_a2l_miss_leaves_rows(tmp_path, case08):
    """R-TUI-040.8/2: the same for the A2L view."""

    async def scenario(app, pilot, log):
        await _miss_leaves_rows(pilot, app, log, case08, "a2l")

    drive(tmp_path, scenario)


def test_r_tui_040_8_3_mac_miss_leaves_rows(tmp_path, case08):
    """R-TUI-040.8/3: the same for the MAC view."""

    async def scenario(app, pilot, log):
        await _miss_leaves_rows(pilot, app, log, case08, "mac")

    drive(tmp_path, scenario)


def test_r_tui_040_8_4_miss_after_jump_to_last_row_keeps_window(tmp_path, case08):
    """R-TUI-040.8/4: a miss after a jump to the last present row leaves the
    rows unchanged: the window still starts at row 26 544 (base: 26 400)."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        bases = app.current_file.row_bases
        assert len(bases) == 26546
        await goto(pilot, app, log, view, f"0x{LAST_ROW:08X}", hit(LAST_ROW))
        await wait_rows(pilot, app, view, [bases[26544], bases[26545]], "jump to the last present row")
        before = [r[2:] for r in hex_rows(app, "#hex_view")]
        await goto(pilot, app, log, view, "0xFFFFFFF0", MISS)
        after = [r[2:] for r in hex_rows(app, "#hex_view")]
        assert after == before, f"the miss moved the window: {len(before)} rows before, {len(after)} after"
        assert addrs(app, "#hex_view", 1) == [bases[26544]], fmt(addrs(app, "#hex_view", 1))

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-040.11 - a failed go-to removes the marker
# ---------------------------------------------------------------------------


async def _marker_removed_by(pilot, app, log, case08, view_name, text: str, status: str) -> None:
    view = await start(pilot, app, case08, view_name)
    _key, hex_id, _scroll, _goto, _search, _field = view
    await goto(pilot, app, log, view, "0x00000050", hit(0x50))
    await wait_until(
        pilot,
        lambda: [addr_of(r) for r in marked_rows(app, hex_id)] == [0x50],
        lambda: f"{view_name}: precondition, marked lines {marked_rows(app, hex_id)!r}",
    )
    await goto(pilot, app, log, view, text, status)
    await wait_no_marker(pilot, app, view, f"{view_name} after go-to {text!r}")


def test_r_tui_040_11_1_main_miss_removes_marker(tmp_path, case08):
    """R-TUI-040.11/1: a main miss removes the marker (base: 1 marked line)."""

    async def scenario(app, pilot, log):
        await _marker_removed_by(pilot, app, log, case08, "main", "0xFFFFFFF0", MISS)

    drive(tmp_path, scenario)


def test_r_tui_040_11_2_main_empty_box_removes_marker(tmp_path, case08):
    """R-TUI-040.11/2: an empty go-to box removes the marker."""

    async def scenario(app, pilot, log):
        await _marker_removed_by(pilot, app, log, case08, "main", "", "Goto address is empty.")

    drive(tmp_path, scenario)


def test_r_tui_040_11_3_main_invalid_address_removes_marker(tmp_path, case08):
    """R-TUI-040.11/3: an invalid address removes the marker (base: 1)."""

    async def scenario(app, pilot, log):
        await _marker_removed_by(pilot, app, log, case08, "main", "zz", "Invalid address format.")

    drive(tmp_path, scenario)


#: The three failures of a go-to (box text, status), one per failure branch of
#: each view's go-to handler (QA-3 at E5: the A2L and MAC branches need a node
#: each).
GOTO_FAILURES = {
    "miss": ("0xFFFFFFF0", MISS),
    "empty": ("", "Goto address is empty."),
    "invalid": ("zz", "Invalid address format."),
}


@pytest.mark.parametrize("failure", ["miss", "empty", "invalid"])
def test_r_tui_040_11_4_a2l_failed_goto_removes_marker(tmp_path, case08, failure):
    """R-TUI-040.11/4 (``[miss]``), /6 (``[empty]``), /7 (``[invalid]``): each
    failed A2L go-to removes the marker (/6, /7 and the parametrisation added
    at E5, QA-3)."""
    text, status = GOTO_FAILURES[failure]

    async def scenario(app, pilot, log):
        await _marker_removed_by(pilot, app, log, case08, "a2l", text, status)

    drive(tmp_path, scenario)


@pytest.mark.parametrize("failure", ["invalid", "empty", "miss"])
def test_r_tui_040_11_5_mac_failed_goto_removes_marker(tmp_path, case08, failure):
    """R-TUI-040.11/5 (``[invalid]``), /8 (``[empty]``), /9 (``[miss]``): each
    failed MAC go-to removes the marker (/8, /9 and the parametrisation added
    at E5, QA-3)."""
    text, status = GOTO_FAILURES[failure]

    async def scenario(app, pilot, log):
        await _marker_removed_by(pilot, app, log, case08, "mac", text, status)

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-040.12 - every other jump removes the marker
# ---------------------------------------------------------------------------


async def _marker_set(pilot, app, log, view) -> None:
    _key, hex_id, _scroll, _goto, _search, field = view
    await goto(pilot, app, log, view, "0x00000050", hit(0x50))
    await wait_until(
        pilot,
        lambda: [addr_of(r) for r in marked_rows(app, hex_id)] == [0x50] and getattr(app, field) == 0x50,
        lambda: f"precondition: marked {marked_rows(app, hex_id)!r}, field {getattr(app, field)!r}",
    )


async def _marker_gone(pilot, app, view, what: str) -> None:
    """The marker address is cleared and no line is marked."""
    _key, hex_id, _scroll, _goto, _search, field = view
    await wait_until(
        pilot,
        lambda: getattr(app, field) is None,
        lambda: f"{what}: the marker address field still holds {getattr(app, field)!r}",
        timeout=FIX_WAIT,
    )
    await wait_no_marker(pilot, app, view, what)


def test_r_tui_040_12_1_section_jump_removes_main_marker(tmp_path, case08):
    """R-TUI-040.12/1: a section jump removes the main marker (base: the marker
    address 0x50 is kept); '.' then ',' leave 0 marked lines."""

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        await _marker_set(pilot, app, log, view)
        sections = app.query_one("#sections_list", ListView)
        last = len(sections.children) - 1
        assert sections.children[last].data[0] == 0x00C00000
        sections.focus()
        await wait_until(pilot, lambda: app.default_screen.focused is sections, "the section list did not take the focus")
        sections.index = last
        await wait_until(pilot, lambda: sections.index == last, "the section cursor did not move")
        shown_before = addrs(app, "#hex_view", 1)
        await pilot.press("enter")
        await wait_until(pilot, lambda: addrs(app, "#hex_view", 1) != shown_before, "the section jump did not move the window")
        await _marker_gone(pilot, app, view, "after the section jump")
        first = addrs(app, "#hex_view", 1)
        await pilot.press("period")
        await wait_until(pilot, lambda: addrs(app, "#hex_view", 1) != first, "'.' did not page")
        assert not marked_rows(app, "#hex_view")
        await pilot.press("comma")
        await wait_until(pilot, lambda: addrs(app, "#hex_view", 1) == first, "',' did not page back")
        assert not marked_rows(app, "#hex_view"), marked_rows(app, "#hex_view")

    drive(tmp_path, scenario)


def test_r_tui_040_12_3_map_open_in_hex_removes_main_marker(tmp_path, case08):
    """R-TUI-040.12/3: a Memory Map open-in-hex removes the main marker."""
    from s19_app.tui.screens_directionb import MemoryMapPanel

    async def scenario(app, pilot, log):
        view = await start(pilot, app, case08, "main")
        await _marker_set(pilot, app, log, view)
        await pilot.press("4")
        panel = app.query_one("#memory_map_panel", MemoryMapPanel)
        await wait_until(pilot, lambda: len(panel._live_region_rows()) >= 2, "the map lists fewer than two regions")
        chosen = panel._live_region_rows()[1].region_start
        await _double_click_region_row(pilot, app, lambda r: r.region_start == chosen)
        await wait_until(
            pilot,
            lambda: app.query_one("#hex_scroll", ScrollableContainer).region.height > 0
            and addrs(app, "#hex_view", 1) != [0x40],
            "the open-in-hex did not show the Workspace at the region",
        )
        await _marker_gone(pilot, app, view, "after the open-in-hex")

    drive(tmp_path, scenario)


async def _continued_search_clears(pilot, app, log, case08, view_name) -> None:
    """Find Next twice on a text with two hits ("19TOOL": the boot banner at
    0x00000001 and the config block), a go-to between them; the second hit is
    in the config region, the shown second row, and the marker is gone."""
    view = await start(pilot, app, case08, view_name)
    await search(pilot, app, log, view, "19TOOL", "Found at 0x00000001")
    await _marker_set(pilot, app, log, view)
    mark = await search(pilot, app, log, view, None, re.compile(r"Found at 0x00C0[0-9A-F]{4}"))
    found = int(_status_match(log, mark, re.compile(r"Found at 0x00C0[0-9A-F]{4}"))[9:], 16)
    row = found - found % 16
    bases = app.current_file.row_bases
    await wait_rows(pilot, app, view, [bases[bisect_left(bases, row) - 1], row], f"{view_name} continued search")
    await _marker_gone(pilot, app, view, f"{view_name} after the continued search")


def test_r_tui_040_12_4_continued_main_find_next_removes_marker(tmp_path, case08):
    """R-TUI-040.12/4: a continued main Find Next shows the hit second and
    removes the marker."""

    async def scenario(app, pilot, log):
        await _continued_search_clears(pilot, app, log, case08, "main")

    drive(tmp_path, scenario)


def test_r_tui_040_12_5_continued_a2l_search_removes_marker(tmp_path, case08):
    """R-TUI-040.12/5: a continued A2L search removes the marker."""

    async def scenario(app, pilot, log):
        await _continued_search_clears(pilot, app, log, case08, "a2l")

    drive(tmp_path, scenario)


def test_r_tui_040_12_6_continued_mac_search_removes_marker(tmp_path, case08):
    """R-TUI-040.12/6: a continued MAC search removes the marker."""

    async def scenario(app, pilot, log):
        await _continued_search_clears(pilot, app, log, case08, "mac")

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-007.3 / .5 / .8 - '.' pages from the shown window
# ---------------------------------------------------------------------------


def test_r_tui_007_3_1_next_page_follows_the_shown_window(tmp_path):
    """R-TUI-007.3/1: after a jump to row 151 of 1 000 (window from row 150)
    '.' starts the window at row 350 (base: page-aligned 200)."""

    async def scenario(app, pilot, log):
        image = write_rows(tmp_path / "rows.s19", 1000)
        app.load_selected_file(image)
        await wait_until(pilot, lambda: app.current_file is not None and app.current_file.path.name == image.name, "load")
        await settle_workers(pilot)
        await wait_until(pilot, lambda: bool(hex_rows(app, "#hex_view")), "no rows painted")
        assert len(app.current_file.row_bases) == 1000 and app.hex_rows_page_size == 200
        await goto(pilot, app, log, MAIN, f"0x{row_at(151):08X}", hit(row_at(151)))
        await wait_rows(pilot, app, MAIN, [row_at(150), row_at(151)], "go-to row 151")
        await pilot.press("period")
        await wait_rows(pilot, app, MAIN, [row_at(350)], "'.' after the jump to row 151")

    drive(tmp_path, scenario)


def test_r_tui_007_5_1_next_page_keeps_a_window_holding_the_last_row(tmp_path):
    """R-TUI-007.5/1: after a jump to row 949 (window from row 948, holding the
    last row) '.' three times keeps the window at row 948 (base: 800)."""

    async def scenario(app, pilot, log):
        image = write_rows(tmp_path / "rows.s19", 1000)
        app.load_selected_file(image)
        await wait_until(pilot, lambda: app.current_file is not None and app.current_file.path.name == image.name, "load")
        await settle_workers(pilot)
        await wait_until(pilot, lambda: bool(hex_rows(app, "#hex_view")), "no rows painted")
        await goto(pilot, app, log, MAIN, f"0x{row_at(949):08X}", hit(row_at(949)))
        await wait_rows(pilot, app, MAIN, [row_at(948), row_at(949)], "go-to row 949")
        # The precondition that makes "window kept" mean something (E5, CR-7):
        # a text box focused here would take '.' as text and keep any window.
        focused = app.default_screen.focused
        assert not isinstance(focused, (Input, TextArea)), (
            f"precondition: '.' would be typed into {type(focused).__name__}#{focused.id}"
        )
        for press in (1, 2, 3):
            await pilot.press("period")
            assert addrs(app, "#hex_view", 1) == [row_at(948)], (
                f"'.' press {press}: first row {fmt(addrs(app, '#hex_view', 1))}, expected {fmt([row_at(948)])}"
            )

    drive(tmp_path, scenario)


def test_r_tui_007_8_1_pages_count_the_row_added_for_a_mac_record(tmp_path):
    """R-TUI-007.8/1: with a MAC record below the image and a page of 3 rows,
    '.' shows 0x00008020 alone and a second '.' keeps it (base: the first page)."""

    async def scenario(app, pilot, log):
        await load_three(pilot, app, tmp_path, mac=True)
        await show(pilot, app, MAIN)
        mark = len(log.messages)
        app._apply_viewer_setting("hex_rows_page_size", 3)
        await wait_status(pilot, log, mark, "Updated hex_rows_page_size to 3.")
        assert app.hex_rows_page_size == 3
        await wait_until(
            pilot,
            lambda: [addr_of(r) for r in hex_rows(app, "#hex_view")] == [0x1000, 0x8000, 0x8010],
            lambda: f"first page: {fmt(addrs(app, '#hex_view', 5))}",
        )
        await pilot.press("period")
        await wait_until(
            pilot,
            lambda: [addr_of(r) for r in hex_rows(app, "#hex_view")] == [0x8020],
            lambda: f"after the first '.': {fmt(addrs(app, '#hex_view', 5))}, expected [0x00008020]",
            timeout=FIX_WAIT,
        )
        await pilot.press("period")
        assert [addr_of(r) for r in hex_rows(app, "#hex_view")] == [0x8020], fmt(addrs(app, "#hex_view", 5))

    drive(tmp_path, scenario)


def test_r_tui_007_9_1_a_load_after_a_deep_jump_shows_the_new_file_from_its_first_row(tmp_path):
    """R-TUI-007.9/1 (added at E4, E4-R1): after a go-to to row 949 of a 1 000-row
    image (window from row 948), loading fixture three shows the new file from its
    first view row: rows 0x00008000, 0x00008010, 0x00008020 and no ``... showing
    from`` notice (the Inc 10a tree before E4-R1: 0x00008020 alone under
    ``... showing from 0x00008020 (context preserved) ...``, int-06; base: the
    whole file, from the page floor)."""

    async def scenario(app, pilot, log):
        image = write_rows(tmp_path / "rows.s19", 1000)
        app.load_selected_file(image)
        await wait_until(pilot, lambda: app.current_file is not None and app.current_file.path.name == image.name, "load")
        await settle_workers(pilot)
        await wait_until(pilot, lambda: bool(hex_rows(app, "#hex_view")), "no rows painted")
        await goto(pilot, app, log, MAIN, f"0x{row_at(949):08X}", hit(row_at(949)))
        await wait_rows(pilot, app, MAIN, [row_at(948), row_at(949)], "go-to row 949")
        three = write_three(tmp_path / "three.s19")
        app.load_selected_file(three)
        await wait_until(
            pilot,
            lambda: app.current_file is not None and app.current_file.path.name == three.name,
            "the load of fixture three",
        )
        await settle_workers(pilot)
        await wait_rows(pilot, app, MAIN, [0x8000, 0x8010, 0x8020], "the load after the deep jump")
        assert len(hex_rows(app, "#hex_view")) == 3, hex_rows(app, "#hex_view")
        showing = [line for line in notices(app, "#hex_view") if "showing from" in line]
        assert showing == [], showing

    drive(tmp_path, scenario)
