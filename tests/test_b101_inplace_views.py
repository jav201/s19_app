"""Batch-101 increment 10b - views that follow in-place writes (tester W of E4).

Written by an independent tester from the approved design only
(``inc-10b/01-requirements.md``, ``02-test-cases.md``, ``E1-slice.md``,
``E1-rulings.md``, ``codewire/graph-inc10b.md``, ``inc-10/E3-rulings.md``,
``inc-10/E3-security.md`` and the Inc 10a testers' notes). No line of the
Inc 10b implementation was read to decide what to assert.

Group W: what the A2L tag table, the three hex panes and the Split / Join
window paint after an in-place write (a Patch Editor apply, a Patch Editor
save-back, a Save project commit).

  - R-A2L-048 / .049 / .105 / .106 - the tag table's Raw and Physical cells
    read the written bytes, and the first shown row, the highlighted row and
    the listed tags stay;
  - R-TUI-004.7 / .8 / .9 - the main, A2L and MAC hex panes show the written
    bytes and keep their shown window, scroll and ``> `` marker;
  - R-SEG-PREV.21 / .22 - a displayed Split / Join preview re-plans a Save
    project commit and keeps the focus;
  - R-SEG-EXP.15 - an in-place write disarms the export confirm.

Oracles are what the app painted: the plain text of the three hex Statics (a
hex row is a line that starts with ``> `` or two spaces and ``0x``), the cells
of ``#a2l_tags_list``, ``#a2l_tags_summary`` and ``#a2l_detail_card``, the
scroll offsets of the scroll containers, the stats and state lines of the
Split / Join window (``#sje_stats``), the blocks the window handed its band
(``#sje_band``) and the files written to disk. Writers are driven through the
shipped controls (the Patch Editor's Load, Apply, entry Edit and Write file
buttons, the Save project dialog). Every wait goes through
``tests/support/timing.py::wait_until``; a fix-only sign is waited for with the
short ``FIX_WAIT`` so that a missing behaviour fails with the painted state in
the message. Every negative assertion follows a positive wait in the same
node. Windows are switched with the rail keys only. ``LOCALAPPDATA`` is
isolated by ``tests/conftest.py``; no case touches the OS clipboard.

Each node that checks a window, a cursor or a marker across a write first runs
a round trip through the Patch Editor with no write and asserts that the round
trip alone changes nothing (the precondition that makes the post-write
comparison a test of the write).
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

import pytest
from textual.containers import ScrollableContainer
from textual.coordinate import Coordinate
from textual.widgets import Button, DataTable, Input, Label, ListView, Static

REPO_ROOT = Path(__file__).resolve().parent.parent
SYNTH_DIR = REPO_ROOT / "tools" / "synth"
if str(SYNTH_DIR) not in sys.path:
    sys.path.insert(0, str(SYNTH_DIR))

import make_release_case as gen  # noqa: E402

from s19_app.tui.screens_directionb import PatchEditorPanel  # noqa: E402
from s19_app.tui.segment_split_view import SplitJoinWindow  # noqa: E402
from tests.support import b100_projects as projects  # noqa: E402
from tests.support import b100_save_dialog as sd  # noqa: E402
from tests.support.b100_workers import settle_workers  # noqa: E402
from tests.support.timing import report_margin, timing_bound, wait_until  # noqa: E402

SEED = 20260001
SIZE_MB = 1.0
SIZE = (120, 56)  # measured screen 118 x 54, the guide's regime

#: Ceiling of a wait for a state only the Inc 10b behaviour reaches.
FIX_WAIT = 15.0

#: A hex view: rail key, window, hex Static, scroll container, go-to input id.
#: Unpacked into plain names before any query (the address census wants
#: literal or plain-name selectors).
MAIN = ("1", "workspace", "#hex_view", "#hex_scroll", "goto_input")
ALT = ("2", "a2l", "#alt_hex_view", "#alt_hex_scroll", "alt_goto_input")
MAC = ("3", "mac", "#mac_hex_view", "#mac_hex_scroll", "mac_goto_input")
VIEWS = {"main": MAIN, "a2l": ALT, "mac": MAC}

FIXTURE_ROW = "FF FF FF AA FF FF FF FF"  # fixture three, 0x8013 = AA, row 0x8010
BAND_ONE = [("data", 8), ("fill", 11), ("conflict", 1), ("fill", 12), ("data", 8)]
BAND_TWO = [("data", 8), ("fill", 13), ("conflict", 2), ("fill", 9), ("data", 8)]
CLOBBER_ONE = "⚠ 1 B would clobber source — abort on export"
CLOBBER_TWO = "⚠ 2 B would clobber source — abort on export"
WILL_ASK = "— e will ask"
AGAIN = "— e again to confirm"


# ---------------------------------------------------------------------------
# Fixtures: images, documents, case 08
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def case08(tmp_path_factory) -> Path:
    """Case 08: seed 20260001, 1.0 MB (462 A2L tags, ``VALUE_0001`` at 0x0)."""
    folder = tmp_path_factory.mktemp("b101_i10bw_case08")
    gen.generate(folder, SEED, SIZE_MB)
    return folder


def _s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def _s2(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 4, (addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]) + data
    return "S2" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


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


def write_guard(path: Path) -> Path:
    """Guard fixture: two 8-byte ranges at 0x0 and 0x100000 (span 1 MiB + 8 B)."""
    lines = [
        "S0030000FC",
        _s2(0x0, bytes(range(1, 9))),
        _s2(0x100000, bytes(range(0x81, 0x89))),
        "S804000000FB",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="ascii")
    return path


def write_mac_below(path: Path) -> Path:
    """One valid MAC record at 0x00001000, outside fixture three."""
    path.write_text("LOW_SYMBOL=0x00001000\n", encoding="utf-8")
    return path


def write_doc(path: Path, entries: list) -> Path:
    """A change document of ``(address, bytes)`` entries."""
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
        content = widget.render()
    return str(getattr(content, "plain", content))


def hex_rows(app, hex_id: str) -> list:
    """The hex row lines of one view, in painted order."""
    lines = plain(app.query_one(hex_id, Static)).splitlines()
    return [ln for ln in lines if ln.startswith(("> ", "  0x"))]


def marked_rows(app, hex_id: str) -> list:
    return [ln for ln in hex_rows(app, hex_id) if ln.startswith("> ")]


def addr_of(row: str) -> int:
    return int(row[2:12], 16)


def addrs(app, hex_id: str, count: int = 0) -> list:
    rows = hex_rows(app, hex_id)
    found = [addr_of(r) for r in rows]
    return found[:count] if count else found


def row_bytes(app, hex_id: str, address: int):
    """The byte cells of the hex row at ``address`` as ``"FF FF ..."`` (blank
    cells dropped), or ``None`` when the row is not painted."""
    tag = f"0x{address:08X}"
    for line in plain(app.query_one(hex_id, Static)).splitlines():
        if line[2:12] == tag:
            return " ".join(line[14:].split(" |")[0].split())
    return None


def fmt(values) -> str:
    return "[" + ", ".join("None" if v is None else f"0x{v:08X}" for v in values) + "]"


def scroll_of(app, scroll_id: str) -> tuple:
    sc = app.query_one(scroll_id, ScrollableContainer)
    return (sc.scroll_x, sc.scroll_y)


# ---------------------------------------------------------------------------
# Drives (keys, buttons, tables, dialogs)
# ---------------------------------------------------------------------------


def panel(app) -> PatchEditorPanel:
    return app.query_one("#patch_editor_panel", PatchEditorPanel)


async def settle(pilot, count: int = 4) -> None:
    for _ in range(count):
        await pilot.pause()


async def load_image(pilot, app, path: Path, *, timeout: float = 60.0) -> None:
    app.load_selected_file(path)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == path.name,
        f"the load of {path.name} did not finish",
        timeout=timeout,
    )
    await settle_workers(pilot)
    await settle(pilot)


async def load_mac(pilot, app, path: Path) -> None:
    app.load_selected_file(path)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.mac_path is not None,
        f"the MAC load of {path.name} did not finish",
    )
    await settle_workers(pilot)
    await settle(pilot)


async def load_a2l(pilot, app, path: Path, *, timeout: float = 60.0) -> None:
    app.load_a2l_from_path(path)
    await wait_until(
        pilot,
        lambda: app.current_a2l_data is not None,
        "the A2L load did not finish",
        timeout=timeout,
    )
    await settle_workers(pilot)
    await settle(pilot)


async def load_case(pilot, app, case08: Path, *, a2l: bool = False, mac: bool = False) -> None:
    """Case 08's image, then its A2L and its MAC when named."""
    await load_image(pilot, app, case08 / "firmware.s19")
    if a2l:
        await load_a2l(pilot, app, case08 / "firmware.a2l")
    if mac:
        await load_mac(pilot, app, case08 / "firmware.mac")


async def open_patch(pilot, app) -> None:
    """Key ``6`` with no text box focused; wait for the Patch Editor."""
    app.set_focus(None)
    await pilot.press("6")
    await wait_until(
        pilot,
        lambda: app._active_screen_key == "patch"
        and len(app.query("#patch_doc_path_input")) > 0
        and app.query_one("#patch_doc_path_input").region.width > 0,
        "the Patch Editor did not show after key 6",
    )
    await settle(pilot)


async def press_shown(pilot, button: Button) -> None:
    """Press ``button`` once it is laid out on the screen (E5 QA-7: the route
    the press stands for is shown, as ``write_file`` checks its button)."""
    await wait_until(
        pilot, lambda: button.region.width > 0, f"#{button.id} is not shown on the screen"
    )
    button.press()


async def load_doc(pilot, app, log, path: Path) -> None:
    """Type the document's path, press Load, wait for the load line."""
    mark = len(log.messages)
    p = panel(app)
    p.query_one("#patch_doc_path_input", Input).value = str(path)
    await press_shown(pilot, p.query_one("#patch_doc_load_button", Button))
    await wait_until(
        pilot,
        lambda: any(m.startswith("Loaded change:") for m in log.since(mark)),
        lambda: f"no 'Loaded change:' line for {path.name}; got {log.since(mark)!r}",
    )
    await settle(pilot)


async def apply_loaded(pilot, app, log) -> None:
    """Press Apply; wait for ``Apply: <n> applied``."""
    mark = len(log.messages)
    await press_shown(pilot, panel(app).query_one("#patch_doc_apply_button", Button))
    await wait_until(
        pilot,
        lambda: any(re.match(r"Apply: [1-9]\d* applied", m) for m in log.since(mark)),
        lambda: f"no apply line; got {log.since(mark)!r}",
    )
    await settle(pilot)


async def edit_entry(pilot, app, log, address: str, data: str) -> None:
    """Edit the entry at ``address`` to ``data`` (no new apply)."""
    mark = len(log.messages)
    p = panel(app)
    p.query_one("#patch_entry_address_input", Input).value = address
    p.query_one("#patch_entry_bytes_input", Input).value = data
    await press_shown(pilot, p.query_one("#patch_entry_edit_button", Button))
    await wait_until(
        pilot,
        lambda: "Patch Editor: entry updated." in log.since(mark),
        lambda: f"entry not updated; got {log.since(mark)!r}",
    )
    await settle(pilot)


async def write_file(pilot, app, log) -> None:
    """Confirm *Save patched image as* (Write file); wait for its outcome."""
    mark = len(log.messages)
    assert await pilot.click("#patch_tab_json"), "click missed #patch_tab_json"
    await wait_until(
        pilot,
        lambda: app.query_one("#patch_saveback_confirm_button").region.width > 0,
        "the save-back row did not show",
    )
    app.query_one("#patch_saveback_confirm_button", Button).press()
    await wait_until(
        pilot,
        lambda: any(
            "Saved + verified" in m or "Patched image saved as" in m for m in log.since(mark)
        ),
        lambda: f"no save-back outcome; got {log.since(mark)!r}",
    )
    await settle_workers(pilot)
    await settle(pilot)


async def patch_apply(pilot, app, log, docs: Path, name: str, entries: list) -> None:
    """Key ``6``, the document typed and loaded, Apply pressed."""
    doc = write_doc(docs / name, entries)
    await open_patch(pilot, app)
    await load_doc(pilot, app, log, doc)
    await apply_loaded(pilot, app, log)


async def save_project(pilot, app, log, name: str = "P") -> None:
    """``ctrl+s``, the Save project dialog confirmed; wait for the commit line."""
    mark = len(log.messages)
    await sd.save_through_dialog(pilot, app, name)
    await wait_until(
        pilot,
        lambda: any(m.startswith("Saved project to") for m in log.since(mark)),
        lambda: f"no 'Saved project to' line; got {log.since(mark)!r}",
    )
    await settle_workers(pilot)
    await settle(pilot)


def mem_at(app, address: int):
    return app.current_file.mem_map.get(address)


# --- hex panes -------------------------------------------------------------


async def show_view(pilot, app, view) -> None:
    """Show the window of ``view`` with its rail key; wait until it is laid out
    and has painted hex rows."""
    key, screen, hex_id, scroll_id, _goto = view
    app.set_focus(None)
    await pilot.press(key)
    await wait_until(
        pilot,
        lambda: app._active_screen_key == screen
        and app.query_one(scroll_id, ScrollableContainer).region.height > 0,
        f"the window of key {key} was not laid out",
    )
    await wait_until(pilot, lambda: bool(hex_rows(app, hex_id)), f"no hex rows painted in {hex_id}")
    if isinstance(app.default_screen.focused, Input):
        app.default_screen.set_focus(None)
        await wait_until(
            pilot,
            lambda: app.default_screen.focused is None,
            "the stray text-box focus was not cleared",
        )


async def focus_input(pilot, app, key: str, input_id: str) -> None:
    await pilot.press(key)
    await wait_until(
        pilot,
        lambda: getattr(app.default_screen.focused, "id", None) == input_id,
        lambda: f"key {key!r} did not focus #{input_id}; "
        f"focused {getattr(app.default_screen.focused, 'id', None)!r}",
    )


async def type_into_focused(pilot, app, input_id: str, text: str) -> None:
    await pilot.press(*list(text))
    await wait_until(
        pilot,
        lambda: app.query_one(f"#{input_id}", Input).value == text,
        lambda: f"#{input_id} holds {app.query_one(f'#{input_id}', Input).value!r}, expected {text!r}",
    )


async def goto(pilot, app, log, view, text: str, address: int) -> None:
    """``g``, the text, Tab, Enter; wait for the ``Goto`` status line."""
    _key, _screen, _hex, _scroll, goto_id = view
    mark = len(log.messages)
    await focus_input(pilot, app, "g", goto_id)
    await type_into_focused(pilot, app, goto_id, text)
    await pilot.press("tab", "enter")
    want = f"Goto 0x{address:08X}"
    await wait_until(
        pilot,
        lambda: want in log.since(mark),
        lambda: f"status {want!r} not written; got {log.since(mark)!r}",
    )
    if isinstance(app.default_screen.focused, Input):
        app.default_screen.set_focus(None)
        await settle(pilot, 2)


async def goto_960(pilot, app, log, view) -> None:
    """Show ``view`` and go to 0x00000960; wait for the window at 0x950."""
    _key, _screen, hex_id, _scroll, _goto = view
    await show_view(pilot, app, view)
    await goto(pilot, app, log, view, "0x00000960", 0x960)
    await wait_until(
        pilot,
        lambda: addrs(app, hex_id, 2) == [0x950, 0x960],
        lambda: f"{hex_id}: first rows {fmt(addrs(app, hex_id, 2))}, expected [0x950, 0x960]",
        timeout=FIX_WAIT,
    )


async def scroll_away(pilot, app, scroll_id: str, *, need_x: bool) -> tuple:
    """Scroll one hex pane to x 10, y 40 (as far as its content allows; the A2L
    and MAC panes have no horizontal range); wait for it."""
    sc = app.query_one(scroll_id, ScrollableContainer)
    sc.scroll_to(x=10, y=40, animate=False)
    await wait_until(
        pilot,
        lambda: sc.scroll_y > 0 and (sc.scroll_x > 0 or not need_x),
        lambda: f"{scroll_id} did not scroll away: ({sc.scroll_x}, {sc.scroll_y})",
    )
    return (sc.scroll_x, sc.scroll_y)


# --- A2L tag table ---------------------------------------------------------


def tag_table(app) -> DataTable:
    return app.query_one("#a2l_tags_list", DataTable)


def name_cell(cell) -> str:
    text = str(cell)
    for glyph in ("✓ ", "· "):
        if text.startswith(glyph):
            return text[len(glyph):]
    return text


def tag_column(table) -> int:
    """The Tag column's index, found by its label (Inc 12 re-orders the tag
    table to Address, Length, Tag, …; E2-6 / E3A-14)."""
    for index, column in enumerate(table.ordered_columns):
        if str(column.label) == "Tag":
            return index
    raise AssertionError(
        f"no Tag column in {[str(c.label) for c in table.ordered_columns]}"
    )


def row_name(app, index: int) -> str:
    table = tag_table(app)
    return name_cell(table.get_row_at(index)[tag_column(table)])


def find_row(app, name: str):
    """The row index of the tag whose full name is ``name``, read from the row
    key's tag (``_a2l_row_key_to_tag``) — never from the painted Tag cell, which
    Inc 12 may shorten."""
    table = tag_table(app)
    for index in range(table.row_count):
        key = table.coordinate_to_cell_key(Coordinate(index, 0)).row_key.value
        tag = app._a2l_row_key_to_tag.get(key)
        if tag is not None and str(tag.get("name")) == name:
            return index
    return None


def raw_phys(app, name: str):
    """``(Raw, Physical)`` painted for the first row named ``name``, or None."""
    index = find_row(app, name)
    if index is None:
        return None
    row = tag_table(app).get_row_at(index)
    return (str(row[4]), str(row[5]))


def summary_span(app) -> str:
    """The ``tags <a>-<b> / <T>`` part of the painted table summary."""
    found = re.search(r"tags \d+-\d+ / \d+", plain(app.query_one("#a2l_tags_summary", Label)))
    return found.group(0) if found else ""


def card_text(app) -> str:
    return plain(app.query_one("#a2l_detail_card"))


async def show_a2l(pilot, app) -> None:
    """Key ``2`` with no text box focused; wait for the tag table with rows."""
    app.set_focus(None)
    await pilot.press("2")
    await wait_until(
        pilot,
        lambda: app._active_screen_key == "a2l"
        and tag_table(app).region.height > 0
        and tag_table(app).row_count > 0,
        "the A2L Explorer did not show its tag table",
    )
    await settle(pilot)


async def filter_raw(pilot, app, text: str) -> None:
    """Pick the Raw field in the filter menu, type ``text`` in the filter box,
    wait until the table lists only rows whose Raw cell holds ``text``."""
    button = app.query_one("#a2l_filter_field", Button)
    button.press()
    await wait_until(
        pilot,
        lambda: not app.query_one("#a2l_filter_menu").has_class("hidden"),
        "the filter menu did not open",
    )
    menu_list = app.query_one("#a2l_filter_menu_list", ListView)
    index = next(
        i for i, item in enumerate(menu_list.children) if getattr(item, "data", None) == "raw_value"
    )
    menu_list.focus()
    await wait_until(pilot, lambda: app.focused is menu_list, "the filter menu list took no focus")
    menu_list.index = index
    await settle(pilot, 2)
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: "raw_value" in str(button.label),
        lambda: f"the filter field is {str(button.label)!r}, not raw_value",
    )
    app.query_one("#a2l_tags_filter_input", Input).value = text

    def only_matching() -> bool:
        table = tag_table(app)
        return 0 < table.row_count and all(
            text in str(table.get_row_at(i)[4]) for i in range(table.row_count)
        )

    await wait_until(
        pilot,
        only_matching,
        lambda: f"the table does not list only Raw cells holding {text!r} "
        f"({tag_table(app).row_count} rows)",
    )
    await settle(pilot)


# --- Split / Join ----------------------------------------------------------


def window(app) -> SplitJoinWindow:
    return app.query_one("#screen_split_join", SplitJoinWindow)


def stats_lines(app) -> list:
    return [line.rstrip() for line in str(app.query_one("#sje_stats").render()).split("\n")]


def state_line(app) -> str:
    lines = stats_lines(app)
    return lines[1] if len(lines) > 1 else ""


def band_blocks(app) -> list:
    """The ``(class, size)`` blocks the window handed its band."""
    return [(b.cls, b.size) for b in app.query_one("#sje_band")._blocks]


def joined_files(root: Path) -> list:
    """Every export file (``*_joined*``) anywhere under ``root``."""
    return sorted(p.name for p in root.rglob("*") if p.is_file() and "_joined" in p.name)


async def open_by_palette(pilot, app) -> SplitJoinWindow:
    """``ctrl+k``, the entry's name typed, ``enter`` (the window is palette-only);
    wait for its table to hold the focus."""
    await pilot.press("ctrl+k")
    await wait_until(
        pilot,
        lambda: app.focused is not None and app.focused.id == "palette_input",
        "the palette filter input did not take the focus",
    )
    await pilot.press(*"Split / Join / Export")
    await wait_until(
        pilot,
        lambda: "Split / Join / Export" in app.query_one("#command_bar").visible_palette_labels(),
        "the palette did not list the Split / Join / Export entry",
    )
    await pilot.press("enter")
    await wait_until(
        pilot,
        lambda: app.focused is not None and app.focused.id == "sje_table",
        "the Split / Join / Export window did not open with its table focused",
    )
    return window(app)


async def tick_by_keys(pilot, app, rows: list) -> None:
    """Tick ``rows`` (ascending) with ``down`` and ``space`` from row 0."""
    win = window(app)
    at = 0
    for row in rows:
        await pilot.press(*(["down"] * (row - at)))
        await pilot.press("space")
        at = row
    await wait_until(
        pilot,
        lambda: win._sel["ranges"] == set(rows),
        lambda: f"ticks {win._sel['ranges']!r}, not {set(rows)!r}",
    )


async def join_fill_ff(pilot, app) -> None:
    """Pad ``0xFF`` (``p``), join (``m``), fill (``g``), each waited on."""
    win = window(app)
    if win._pad_int != 0xFF:
        await pilot.press("p")
        await wait_until(pilot, lambda: win._pad_int == 0xFF, "p did not set pad 0xFF")
    await pilot.press("m")
    await wait_until(pilot, lambda: win._mode == "join", "m did not set join")
    await pilot.press("g")
    await wait_until(pilot, lambda: win._gap == "fill", "g did not set fill")


async def sj_scene(pilot, app, log, tmp_path: Path):
    """Fixture three loaded; 0x8013 = AA applied; a document 0x8015 = BB,
    0x8016 = CC loaded, not applied; Split / Join open, join fill, pad 0xFF,
    ranges 0 and 2 ticked. Returns the document's path."""
    docs = app.workarea / "patches"
    await load_image(pilot, app, write_three(tmp_path / "img" / "three.s19"))
    await patch_apply(pilot, app, log, docs, "a.json", [(0x8013, b"\xaa")])
    second = write_doc(docs / "b.json", [(0x8015, b"\xbb"), (0x8016, b"\xcc")])
    await load_doc(pilot, app, log, second)
    assert panel(app).query_one("#patch_doc_entries_table", DataTable).row_count == 2
    await open_by_palette(pilot, app)
    await join_fill_ff(pilot, app)
    await tick_by_keys(pilot, app, [0, 2])
    await wait_until(
        pilot,
        lambda: band_blocks(app) == BAND_ONE and state_line(app) == CLOBBER_ONE,
        lambda: f"precondition: band {band_blocks(app)!r}, state {state_line(app)!r}",
    )
    return second


# ---------------------------------------------------------------------------
# R-A2L-048 - the tag table shows the values of the written bytes
# ---------------------------------------------------------------------------


def test_r_a2l_048_1_apply_shows_in_the_tag_table(tmp_path: Path, case08: Path) -> None:
    """R-A2L-048 case /1: case 08 and its A2L, key ``2`` (``VALUE_0001`` Raw
    ``108``); key ``6``, a document ``0x0`` = ``93`` loaded and applied; key
    ``2`` -> the ``VALUE_0001`` row reads Raw ``147``, Physical ``147``.

    Why: the cell was cached across the write and read the old byte (base:
    ``108`` / ``108``, cache key unchanged, uncached value ``147``). Negative
    control: the enrichment cache kept across the write -> ``108`` -> RED."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await show_a2l(pilot, app)
        assert raw_phys(app, "VALUE_0001") == ("108", "108"), raw_phys(app, "VALUE_0001")
        assert mem_at(app, 0x0) == 0x6C
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x0, b"\x93")])
        assert mem_at(app, 0x0) == 0x93, "the apply did not write"
        await show_a2l(pilot, app)
        await wait_until(
            pilot,
            lambda: raw_phys(app, "VALUE_0001") == ("147", "147"),
            lambda: f"VALUE_0001 paints {raw_phys(app, 'VALUE_0001')!r}, expected ('147', '147')",
            timeout=FIX_WAIT,
        )

    drive(tmp_path, scenario)


def test_r_a2l_048_2_save_project_commit_shows_in_the_tag_table(
    tmp_path: Path, case08: Path
) -> None:
    """R-A2L-048 case /2: as /1 after the apply, the entry edited to ``55``
    without a new apply, key ``2`` (the A2L Explorer displayed); ``ctrl+s``,
    Save project confirmed -> Raw ``85``, Physical ``85``.

    Why: a Save project commit re-derives the image in place, so the value
    painted from the apply (``147``) is stale. Negative control: the commit's
    write not reaching the table -> ``147`` (or ``108``) -> RED."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x0, b"\x93")])
        await edit_entry(pilot, app, log, "0x0", "55")
        assert mem_at(app, 0x0) == 0x93, "the edit must not write (no new apply)"
        await show_a2l(pilot, app)
        await save_project(pilot, app, log)
        assert mem_at(app, 0x0) == 0x55, "the commit did not write"
        await wait_until(
            pilot,
            lambda: raw_phys(app, "VALUE_0001") == ("85", "85"),
            lambda: f"VALUE_0001 paints {raw_phys(app, 'VALUE_0001')!r}, expected ('85', '85')",
            timeout=FIX_WAIT,
        )

    drive(tmp_path, scenario)


def test_r_a2l_048_3_save_back_shows_in_the_tag_table(tmp_path: Path, case08: Path) -> None:
    """R-A2L-048 case /3: as /2 before ``ctrl+s``; *Save patched image as*
    confirmed (Write file); key ``2`` -> Raw ``85``, Physical ``85``.

    Why: a save-back re-derives the image in place. Negative control: the
    save-back's call to the in-place-write hook removed -> the table keeps the
    value of the apply -> RED."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x0, b"\x93")])
        await edit_entry(pilot, app, log, "0x0", "55")
        assert mem_at(app, 0x0) == 0x93, "the edit must not write (no new apply)"
        await write_file(pilot, app, log)
        assert mem_at(app, 0x0) == 0x55, "the save-back did not write"
        await show_a2l(pilot, app)
        await wait_until(
            pilot,
            lambda: raw_phys(app, "VALUE_0001") == ("85", "85"),
            lambda: f"VALUE_0001 paints {raw_phys(app, 'VALUE_0001')!r}, expected ('85', '85')",
            timeout=FIX_WAIT,
        )

    drive(tmp_path, scenario)


def painted_cell(app, index: int, column: int) -> str:
    """The text the tag table paints in its row ``index`` and ``column`` (the
    rendered line cut at the column's painted width; the header is line 0).

    A fixed column paints at its left edge regardless of the horizontal
    scroll, so its start is the plain prefix of render widths; every later
    column starts that prefix minus ``scroll_x``, clamped below the fixed
    columns when the cell is the first partially visible one (R-A2L-048/4)."""
    table = tag_table(app)
    line = table.render_line(1 + index - int(table.scroll_y)).text
    columns = table.ordered_columns
    start = sum(c.get_render_width(table) for c in columns[:column])
    if column >= int(table.fixed_columns):
        fixed_width = sum(
            c.get_render_width(table) for c in columns[: int(table.fixed_columns)]
        )
        start = max(fixed_width, start - int(table.scroll_x))
    return line[start:start + columns[column].get_render_width(table)].strip()


#: R-A2L-048/4: four bytes that make ``VALUE_0007`` (a big-endian FLOAT32 at
#: ``0x00040028``) read a 22-character value.
WIDE_FLOAT = bytes.fromhex("EAA364C6")


def test_r_a2l_048_4_a_wider_value_is_painted_whole(tmp_path: Path, case08: Path) -> None:
    """R-A2L-048 case /4 (robustness, E5 QA-2): case 08 and its A2L, key ``2``
    (page 1; the Raw and Physical columns are 18 cells wide, the widest value
    they have painted); the cursor on ``VALUE_0007`` (row 14, Raw
    ``85.6589584350586``) and the table scrolled right so Raw is its first shown
    column (the table is 50 cells wide); key ``6``, ``0x00040028`` = ``EA A3 64 C6`` applied;
    key ``2`` -> the row paints its Raw cell ``-9.876539885039906e+25`` whole
    (22 characters) and its Physical cell whole, both columns are at least 22
    cells wide, and the scroll and the cursor are unchanged.

    The table's columns only widen (Textual keeps their widths across the
    page refill), so the case needs a written value wider than any value the
    column has painted, not only wider than the cells on screen.

    Why: a written value wider than its column is painted at the old width
    unless the cell write widens the column (R2-7), so the screen would show
    a cut number while the stored cell holds the written one. Base: Raw
    ``85.6589584350586`` -> RED at the value wait. Negative control: the cells
    written with ``update_width=False`` (the call's default) -> the painted
    cells are cut at 18 -> RED."""
    import struct

    expected_raw = str(struct.unpack(">f", WIDE_FLOAT)[0])

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await show_a2l(pilot, app)
        table = tag_table(app)
        raw_column, phys_column = table.ordered_columns[4], table.ordered_columns[5]
        assert (str(raw_column.label), str(phys_column.label)) == ("Raw", "Physical")
        assert row_name(app, 14) == "VALUE_0007", row_name(app, 14)
        assert raw_phys(app, "VALUE_0007") == ("85.6589584350586", "185.6589584350586")
        # the table is narrower than its columns: scroll it so Raw is its first shown column
        raw_x = sum(c.get_render_width(table) for c in table.ordered_columns[:4])
        table.scroll_to(x=raw_x, animate=False)
        await wait_until(pilot, lambda: table.scroll_x == raw_x, lambda: f"scroll_x {table.scroll_x}")
        assert painted_cell(app, 14, 4) == "85.6589584350586", painted_cell(app, 14, 4)
        assert max(raw_column.content_width, phys_column.content_width) < len(expected_raw), (
            f"the columns are already {raw_column.content_width} / "
            f"{phys_column.content_width} cells wide"
        )
        table.move_cursor(row=14, animate=False)
        await wait_until(
            pilot, lambda: table.cursor_row == 14, lambda: f"cursor row {table.cursor_row}"
        )
        first, cursor = (int(table.scroll_x), int(table.scroll_y)), table.cursor_row
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x40028, WIDE_FLOAT)])
        assert bytes(mem_at(app, 0x40028 + i) for i in range(4)) == WIDE_FLOAT, "no write"
        await show_a2l(pilot, app)
        await wait_until(
            pilot,
            lambda: (raw_phys(app, "VALUE_0007") or ("",))[0] == expected_raw,
            lambda: f"VALUE_0007 holds {raw_phys(app, 'VALUE_0007')!r}, expected Raw "
            f"{expected_raw!r}",
            timeout=FIX_WAIT,
        )
        stored_phys = raw_phys(app, "VALUE_0007")[1]
        assert len(stored_phys) >= len(expected_raw), stored_phys
        await wait_until(
            pilot,
            lambda: (painted_cell(app, 14, 4), painted_cell(app, 14, 5))
            == (expected_raw, stored_phys),
            lambda: f"the row paints Raw {painted_cell(app, 14, 4)!r}, Physical "
            f"{painted_cell(app, 14, 5)!r}; columns {raw_column.content_width} / "
            f"{phys_column.content_width} cells",
            timeout=FIX_WAIT,
        )
        assert raw_column.content_width >= len(expected_raw), raw_column.content_width
        assert phys_column.content_width >= len(stored_phys), phys_column.content_width
        assert ((int(table.scroll_x), int(table.scroll_y)), table.cursor_row) == (first, cursor)
        assert row_name(app, 14) == "VALUE_0007"

    drive(tmp_path, scenario)


def test_r_a2l_048_5_a_write_on_the_second_page_shows_there(tmp_path: Path, case08: Path) -> None:
    """R-A2L-048 case /5 (robustness, E5 R-4): case 08 and its A2L, key ``2``,
    ``+`` (page 2: ``tags 201-400 / 462``); the cursor on page row 4
    (``MEASUREMENT_0021``: a 1-byte tag at ``0x00040F00``, Raw ``226``); key
    ``6``, ``0x00040F00`` = ``E1`` applied; key ``2`` -> the row reads Raw
    ``225``, Physical ``225``; the summary still reads ``tags 201-400 / 462``;
    the page's row names are unchanged and the cursor stays on row 4.

    Why: the repaint writes page row ``i`` from the listed tag ``start + i``;
    one that reads tag ``i`` paints page 1's tags over page 2 (every other A2L
    node stays on page 1). Base: Raw ``226`` -> RED. Negative control:
    ``tags[i]`` -> ``MEASUREMENT_0021`` is no longer painted and the row names
    change -> RED.

    The fixture moved off ``VAL_BLK_0002``: Inc 11 renders that tag's
    Raw/Physical cells intentionally blank, so a decoded-value oracle there
    can no longer assert anything. ``MEASUREMENT_0021`` (page row 4) keeps its
    decoded values under Inc 11 and sits on page 2, so the case's second-page
    purpose is preserved."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await show_a2l(pilot, app)
        await pilot.press("plus")
        await wait_until(
            pilot,
            lambda: summary_span(app) == "tags 201-400 / 462",
            lambda: f"+ did not page: the summary reads {summary_span(app)!r}",
        )
        await settle(pilot)
        table = tag_table(app)
        assert row_name(app, 4) == "MEASUREMENT_0021", row_name(app, 4)
        assert raw_phys(app, "MEASUREMENT_0021") == ("226", "226"), raw_phys(app, "MEASUREMENT_0021")
        assert mem_at(app, 0x40F00) == 0xE2
        table.move_cursor(row=4, animate=False)
        await wait_until(
            pilot, lambda: table.cursor_row == 4, lambda: f"cursor row {table.cursor_row}"
        )
        names = [row_name(app, i) for i in range(table.row_count)]
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x40F00, b"\xE1")])
        assert mem_at(app, 0x40F00) == 0xE1, "the apply did not write"
        await show_a2l(pilot, app)
        await wait_until(
            pilot,
            lambda: raw_phys(app, "MEASUREMENT_0021") == ("225", "225"),
            lambda: f"MEASUREMENT_0021 paints {raw_phys(app, 'MEASUREMENT_0021')!r}, expected 225",
            timeout=FIX_WAIT,
        )
        assert summary_span(app) == "tags 201-400 / 462", summary_span(app)
        assert [row_name(app, i) for i in range(table.row_count)] == names, "the row names changed"
        assert table.cursor_row == 4 and row_name(app, 4) == "MEASUREMENT_0021", table.cursor_row
        # E5 RR-4: the row key of page row 4 (``a2l:204``) maps to the new dict;
        # the card for that row is the one the highlight resolves through it.
        row_key = table.coordinate_to_cell_key(Coordinate(4, 0)).row_key.value
        assert row_key == "a2l:204", row_key
        assert str(app._a2l_row_key_to_tag[row_key]["raw_value"]) == "225", (
            app._a2l_row_key_to_tag[row_key]["raw_value"]
        )
        table.move_cursor(row=3, animate=False)
        await wait_until(
            pilot, lambda: "MEASUREMENT_0020" in card_text(app), lambda: card_text(app)
        )
        table.move_cursor(row=4, animate=False)
        await wait_until(
            pilot,
            lambda: "MEASUREMENT_0021" in card_text(app),
            lambda: f"the card for row 4 reads {card_text(app)!r}",
        )
        # E5 RR-1: the recomputed list is the one installed - a filter on the new
        # Raw value lists the written tag, built from ``_a2l_enriched_tags``.
        await filter_raw(pilot, app, "225")
        assert raw_phys(app, "MEASUREMENT_0021") == ("225", "225"), raw_phys(app, "MEASUREMENT_0021")

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-A2L-049 / .105 / .106 - the table keeps its place and its tags
# ---------------------------------------------------------------------------


async def first_shown_scenario(pilot, app, log, case08: Path, tmp_path: Path, raw_filter: str) -> None:
    """The shared drive of R-A2L-049 /1 (``raw_filter`` empty) and /2."""
    await load_case(pilot, app, case08, a2l=True)
    await show_a2l(pilot, app)
    if raw_filter:
        await filter_raw(pilot, app, raw_filter)
    table = tag_table(app)
    assert table.row_count > 41, f"only {table.row_count} rows listed"
    assert find_row(app, "VALUE_0001") is not None, "VALUE_0001 is not listed"
    table.scroll_to(y=30, animate=False)
    await wait_until(pilot, lambda: table.scroll_y == 30, lambda: f"scroll_y {table.scroll_y}")
    first = int(table.scroll_y)
    tag = row_name(app, first)
    listed = [row_name(app, i) for i in range(table.row_count)]
    # control: a round trip through the Patch Editor with no write keeps the place
    await open_patch(pilot, app)
    await show_a2l(pilot, app)
    assert (int(table.scroll_y), row_name(app, int(table.scroll_y))) == (first, tag), (
        f"the round trip alone moved the table to scroll_y {table.scroll_y}"
    )
    before = raw_phys(app, "VALUE_0001")
    await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x0, b"\x93")])
    await show_a2l(pilot, app)
    await wait_until(
        pilot,
        lambda: raw_phys(app, "VALUE_0001") == ("147", "147"),
        lambda: f"the repaint did not happen: VALUE_0001 paints {raw_phys(app, 'VALUE_0001')!r} "
        f"(before {before!r})",
        timeout=FIX_WAIT,
    )
    assert int(table.scroll_y) == first, (
        f"the first shown row moved: scroll_y {table.scroll_y}, was {first}"
    )
    assert row_name(app, int(table.scroll_y)) == tag
    assert [row_name(app, i) for i in range(table.row_count)] == listed, "the listed tags changed"


def test_r_a2l_049_1_first_shown_row_is_kept(tmp_path: Path, case08: Path) -> None:
    """R-A2L-049 case /1: the table scrolled so the page's row 30 is the first
    shown row; the apply of R-A2L-048/1 -> the first shown row is the same tag.

    Why: a clear-and-refill repaint sends the table back to row 0 (E3
    architect P4: ``scroll_y`` 30 -> 0). The node first waits for the repaint
    itself (``VALUE_0001`` Raw ``147``): base paints nothing, so it is RED
    there at that wait. Negative control: the repaint clears the table ->
    ``scroll_y`` 0 -> RED."""

    async def scenario(app, pilot, log):
        await first_shown_scenario(pilot, app, log, case08, tmp_path, "")

    drive(tmp_path, scenario)


def test_r_a2l_049_2_first_shown_row_is_kept_with_a_value_filter(
    tmp_path: Path, case08: Path
) -> None:
    """R-A2L-049 case /2: as /1 with the filter on Raw, text ``1``; the table
    scrolled so the page's row 30 is the first shown row -> the same tag
    stays first shown after the apply.

    Why: the same, with a Raw filter on. Negative control: the filter re-run
    at the write or a clear and refill -> the first shown row changes -> RED."""

    async def scenario(app, pilot, log):
        await first_shown_scenario(pilot, app, log, case08, tmp_path, "1")

    drive(tmp_path, scenario)


def test_r_a2l_105_1_highlighted_row_is_kept(tmp_path: Path, case08: Path) -> None:
    """R-A2L-105 case /1: the cursor on the page's row 40; the apply of
    R-A2L-048/1 -> cursor row 40, the same tag, and the detail card names that
    tag.

    Why: a clear-and-refill repaint puts the cursor on row 0 (P4: 40 -> 0) and
    the card on another tag. The node waits for the repaint first (base paints
    nothing: RED at that wait). Negative control: the repaint clears the table
    -> cursor 0 -> RED."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await show_a2l(pilot, app)
        table = tag_table(app)
        assert table.row_count > 41, f"only {table.row_count} rows listed"
        table.move_cursor(row=40, animate=False)
        await wait_until(
            pilot, lambda: table.cursor_row == 40, lambda: f"cursor row {table.cursor_row}"
        )
        tag = row_name(app, 40)
        await wait_until(
            pilot,
            lambda: tag in card_text(app),
            lambda: f"the detail card does not name {tag!r}: {card_text(app)!r}",
        )
        card_before = card_text(app)
        # control: a round trip through the Patch Editor with no write keeps both
        await open_patch(pilot, app)
        await show_a2l(pilot, app)
        assert table.cursor_row == 40 and card_text(app) == card_before, (
            f"the round trip alone moved the cursor to {table.cursor_row}"
        )
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x0, b"\x93")])
        await show_a2l(pilot, app)
        await wait_until(
            pilot,
            lambda: raw_phys(app, "VALUE_0001") == ("147", "147"),
            lambda: f"the repaint did not happen: VALUE_0001 paints {raw_phys(app, 'VALUE_0001')!r}",
            timeout=FIX_WAIT,
        )
        assert table.cursor_row == 40, f"the cursor moved to row {table.cursor_row}"
        assert row_name(app, table.cursor_row) == tag
        assert tag in card_text(app), f"the detail card lost {tag!r}: {card_text(app)!r}"
        assert card_text(app) == card_before

    drive(tmp_path, scenario)


def test_r_a2l_106_1_value_filter_rows_stay_listed(tmp_path: Path, case08: Path) -> None:
    """R-A2L-106 case /1: case 08 and its A2L, key ``2``, the filter on Raw
    with the text ``108`` (``VALUE_0001`` listed); key ``6``, ``0x0`` = ``93``
    applied; key ``2`` -> ``VALUE_0001`` is still listed with Raw ``147`` and
    the summary's ``tags <a>-<b> / <T>`` equals the one before.

    Why: re-running the filter at the write would drop the row whose value no
    longer matches. Negative control: the filter re-run at the write ->
    ``VALUE_0001`` no longer listed -> RED."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True)
        await show_a2l(pilot, app)
        await filter_raw(pilot, app, "108")
        assert raw_phys(app, "VALUE_0001") == ("108", "108"), "VALUE_0001 is not listed"
        span_before = summary_span(app)
        count_before = tag_table(app).row_count
        assert span_before, "the table summary paints no tags a-b / T"
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x0, b"\x93")])
        await show_a2l(pilot, app)
        await wait_until(
            pilot,
            lambda: raw_phys(app, "VALUE_0001") == ("147", "147"),
            lambda: f"VALUE_0001 paints {raw_phys(app, 'VALUE_0001')!r}, expected ('147', '147')",
            timeout=FIX_WAIT,
        )
        assert tag_table(app).row_count == count_before, "the listed row count changed"
        assert summary_span(app) == span_before, (summary_span(app), span_before)

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-004.7 - an in-place write shows in the three hex views
# ---------------------------------------------------------------------------


def test_r_tui_004_7_1_apply_shows_in_the_main_hex_view(tmp_path: Path) -> None:
    """R-TUI-004.7 case /1: fixture three, Workspace; key ``6``, a document
    ``0x8013`` = ``AA`` loaded and applied; key ``1`` -> ``#hex_view`` row
    ``0x00008010`` = ``FF FF FF AA FF FF FF FF`` and the rows have not jumped.

    Why: the pane was never re-rendered after a write (E3 security P1: base
    ``FF FF FF FF ...``). Negative control: the hex re-render removed from
    the write notice -> ``FF FF FF FF ...`` -> RED."""
    main_key, main_screen, main_hex, main_scroll, main_goto = MAIN

    async def scenario(app, pilot, log):
        await load_image(pilot, app, write_three(tmp_path / "img" / "three.s19"))
        await show_view(pilot, app, MAIN)
        rows_before = addrs(app, main_hex)
        assert row_bytes(app, main_hex, 0x8010) == "FF FF FF FF FF FF FF FF"
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x8013, b"\xaa")])
        assert mem_at(app, 0x8013) == 0xAA, "the apply did not write"
        await show_view(pilot, app, MAIN)
        await wait_until(
            pilot,
            lambda: row_bytes(app, main_hex, 0x8010) == FIXTURE_ROW,
            lambda: f"#hex_view row 0x8010 paints {row_bytes(app, main_hex, 0x8010)!r}, "
            f"expected {FIXTURE_ROW!r}",
            timeout=FIX_WAIT,
        )
        assert addrs(app, main_hex) == rows_before, "the pane jumped after the write"

    drive(tmp_path, scenario)


def test_r_tui_004_7_2_save_back_shows_in_the_a2l_hex_view(tmp_path: Path, case08: Path) -> None:
    """R-TUI-004.7 case /2: fixture three and case 08's A2L; a save-back's bytes
    -> key ``2``: ``#alt_hex_view`` row ``0x00008010`` = ``FF FF FF AA FF FF FF FF``.

    The write reaches the image only through the save-back: the document is
    applied with ``0x8013`` = ``11`` (the *Save patched image as* row shows only
    after an apply), the entry is edited to ``AA`` with no new apply, and
    *Write file* is confirmed (finding W-1: the case's "loaded, not applied"
    is not reachable through the shipped controls). Base: the pane keeps
    ``FF FF FF FF ...``. Negative control: the save-back's notice removed ->
    the pane shows ``11`` or ``FF`` there -> RED."""
    alt_key, alt_screen, alt_hex, alt_scroll, alt_goto = ALT

    async def scenario(app, pilot, log):
        await load_image(pilot, app, write_three(tmp_path / "img" / "three.s19"))
        await load_a2l(pilot, app, case08 / "firmware.a2l")
        await show_view(pilot, app, ALT)
        rows_before = addrs(app, alt_hex)
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x8013, b"\x11")])
        await edit_entry(pilot, app, log, "0x8013", "AA")
        assert mem_at(app, 0x8013) == 0x11, "the edit must not write (no new apply)"
        await write_file(pilot, app, log)
        assert mem_at(app, 0x8013) == 0xAA, "the save-back did not write"
        await show_view(pilot, app, ALT)
        await wait_until(
            pilot,
            lambda: row_bytes(app, alt_hex, 0x8010) == FIXTURE_ROW,
            lambda: f"#alt_hex_view row 0x8010 paints {row_bytes(app, alt_hex, 0x8010)!r}, "
            f"expected {FIXTURE_ROW!r}",
            timeout=FIX_WAIT,
        )
        assert addrs(app, alt_hex) == rows_before, "the pane jumped after the write"

    drive(tmp_path, scenario)


def test_r_tui_004_7_3_save_project_commit_shows_in_the_mac_hex_view(tmp_path: Path) -> None:
    """R-TUI-004.7 case /3: fixture three and a MAC; the document ``0x8013`` =
    ``AA`` loaded, not applied; ``ctrl+s``, Save project confirmed; key ``3`` ->
    ``#mac_hex_view`` row ``0x00008010`` = ``FF FF FF AA FF FF FF FF``.

    Why: the commit writes the document's bytes into the image in place and
    the pane was never re-rendered. Negative control: the commit's notice
    removed -> ``FF FF FF FF ...`` -> RED."""
    mac_key, mac_screen, mac_hex, mac_scroll, mac_goto = MAC

    async def scenario(app, pilot, log):
        await load_image(pilot, app, write_three(tmp_path / "img" / "three.s19"))
        await load_mac(pilot, app, write_mac_below(tmp_path / "img" / "below.mac"))
        await show_view(pilot, app, MAC)
        rows_before = addrs(app, mac_hex)
        doc = write_doc(app.workarea / "patches" / "d.json", [(0x8013, b"\xaa")])
        await open_patch(pilot, app)
        await load_doc(pilot, app, log, doc)
        assert mem_at(app, 0x8013) == 0xFF, "the document must not be applied"
        await save_project(pilot, app, log)
        assert mem_at(app, 0x8013) == 0xAA, "the commit did not write"
        await show_view(pilot, app, MAC)
        await wait_until(
            pilot,
            lambda: row_bytes(app, mac_hex, 0x8010) == FIXTURE_ROW,
            lambda: f"#mac_hex_view row 0x8010 paints {row_bytes(app, mac_hex, 0x8010)!r}, "
            f"expected {FIXTURE_ROW!r}",
            timeout=FIX_WAIT,
        )
        assert addrs(app, mac_hex) == rows_before, "the pane jumped after the write"

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-TUI-004.8 / .9 - the shown window and the marker survive the write
# ---------------------------------------------------------------------------


def loads_for(view_name: str) -> dict:
    """The artifacts a case loads for one view (image always)."""
    return {"main": {}, "a2l": {"a2l": True}, "mac": {"mac": True}}[view_name]


@pytest.mark.parametrize("view_name", ["main", "a2l", "mac"])
def test_r_tui_004_8_shown_window_is_kept(tmp_path: Path, case08: Path, view_name: str) -> None:
    """R-TUI-004.8 cases /1 (main), /2 (A2L), /3 (MAC): case 08 (with the A2L or
    the MAC for its view); a go-to ``0x00000960`` (first hex row
    ``0x00000950``), the pane scrolled to (x 10, y 40) (the A2L and MAC panes
    have no horizontal range: y 40 and the x they reach); the complement of the
    byte at ``0x00000965`` applied; the view shown again -> first hex row
    ``0x00000950`` and the same scroll.

    The scroll reached before the write is pinned: (10, 40) in the main pane,
    (0, 40) in the A2L and MAC panes, which have no horizontal range at 118 x
    54 (E5 QA-4).

    Why: a re-render that takes the written address as a jump target moves the
    window and resets the scroll. The node waits until the pane changed after
    the write (the written byte painted at ``0x960``, or the window moved):
    base never re-renders, so it is RED at that wait; a re-render from another
    window is RED at the window clause (M-B2, E5 QA-4), one that resets the
    scroll at the scroll clause (M-B). Negative control: the re-render takes
    the written address as a jump target -> the window moves, the scroll
    resets -> RED."""
    view = VIEWS[view_name]
    _key, _screen, hex_id, scroll_id, _goto = view

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, **loads_for(view_name))
        await goto_960(pilot, app, log, view)
        scroll = await scroll_away(pilot, app, scroll_id, need_x=(view_name == "main"))
        assert scroll == ((10, 40) if view_name == "main" else (0, 40)), (
            f"{scroll_id} reached {scroll} before the write"
        )
        old_row = row_bytes(app, hex_id, 0x960)
        assert old_row is not None
        old = mem_at(app, 0x965)
        assert old_row.split()[5] == f"{old:02X}", (old_row, old)
        new = old ^ 0xFF
        # control: a round trip through the Patch Editor with no write keeps the window
        await open_patch(pilot, app)
        await show_view(pilot, app, view)
        assert addrs(app, hex_id, 2) == [0x950, 0x960] and scroll_of(app, scroll_id) == scroll, (
            f"the round trip alone changed the window: {fmt(addrs(app, hex_id, 2))}, "
            f"{scroll_of(app, scroll_id)} (was {scroll})"
        )
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x965, bytes([new]))])
        assert mem_at(app, 0x965) == new, "the apply did not write"
        await show_view(pilot, app, view)
        tokens = old_row.split()
        tokens[5] = f"{new:02X}"
        expected = " ".join(tokens)
        await wait_until(
            pilot,
            lambda: row_bytes(app, hex_id, 0x960) == expected
            or addrs(app, hex_id, 2) != [0x950, 0x960],
            lambda: f"{hex_id} row 0x960 paints {row_bytes(app, hex_id, 0x960)!r}, "
            f"expected {expected!r}",
            timeout=FIX_WAIT,
        )
        assert addrs(app, hex_id, 2) == [0x950, 0x960], (
            f"the shown window moved: first rows {fmt(addrs(app, hex_id, 2))}"
        )
        assert row_bytes(app, hex_id, 0x960) == expected, (
            f"{hex_id} row 0x960 paints {row_bytes(app, hex_id, 0x960)!r}, expected {expected!r}"
        )
        assert scroll_of(app, scroll_id) == scroll, (
            f"the scroll changed: {scroll_of(app, scroll_id)}, was {scroll}"
        )

    drive(tmp_path, scenario)


def test_r_tui_004_9_1_markers_survive_a_write(tmp_path: Path, case08: Path) -> None:
    """R-TUI-004.9 case /1: case 08 with its A2L and MAC; a go-to
    ``0x00000960`` in each of the three views; the apply of R-TUI-004.8/1 ->
    in each view exactly one line starts with ``> ``, the ``0x00000960`` row.

    Why: a re-render that passes a focus address clears the marker. The node
    waits for the re-render itself (the written byte painted at ``0x960`` in
    the view) before it reads the marker: base never re-renders, so it is RED
    at that wait, and the marker clause is first observable with the fix.
    Negative control: the re-render passes a focus address (the marker is
    cleared) -> 0 marked lines -> RED."""

    async def scenario(app, pilot, log):
        await load_case(pilot, app, case08, a2l=True, mac=True)
        for view in (MAIN, ALT, MAC):
            await goto_960(pilot, app, log, view)
        old_row = row_bytes(app, "#hex_view", 0x960)
        old = mem_at(app, 0x965)
        assert old_row is not None and old_row.split()[5] == f"{old:02X}"
        new = old ^ 0xFF
        tokens = old_row.split()
        tokens[5] = f"{new:02X}"
        expected = " ".join(tokens)

        def marker_report() -> str:
            return "; ".join(
                f"{v[2]}: {[ln[:14] for ln in marked_rows(app, v[2])]!r}" for v in (MAIN, ALT, MAC)
            )

        # control: a round trip through the Patch Editor with no write keeps each marker
        await open_patch(pilot, app)
        for view in (MAIN, ALT, MAC):
            _k, _s, hex_id, _sc, _g = view
            await show_view(pilot, app, view)
            assert [addr_of(r) for r in marked_rows(app, hex_id)] == [0x960], marker_report()
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x965, bytes([new]))])
        assert mem_at(app, 0x965) == new, "the apply did not write"
        for view in (MAIN, ALT, MAC):
            _k, _s, hex_id, _sc, _g = view
            await show_view(pilot, app, view)
            await wait_until(
                pilot,
                lambda: row_bytes(app, hex_id, 0x960) == expected,
                lambda: f"{hex_id} row 0x960 paints {row_bytes(app, hex_id, 0x960)!r}, "
                f"expected {expected!r}",
                timeout=FIX_WAIT,
            )
            assert [addr_of(r) for r in marked_rows(app, hex_id)] == [0x960], (
                f"{hex_id}: marked lines {[ln[:14] for ln in marked_rows(app, hex_id)]!r}"
            )

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SEG-PREV.21 / .22 - a displayed Split / Join preview follows a commit
# ---------------------------------------------------------------------------


def test_r_seg_prev_21_1_preview_follows_a_save_project_commit(tmp_path: Path) -> None:
    """R-SEG-PREV.21 case /1: fixture three, ``0x8013`` = ``AA`` applied (band
    ``data 8 . fill 11 . conflict 1 . fill 12 . data 8``); a document ``0x8015``
    = ``BB``, ``0x8016`` = ``CC`` loaded, not applied; Split / Join displayed,
    join fill, pad ``0xFF``, ranges 0 and 2 ticked; Save project confirmed ->
    band ``data 8 . fill 13 . conflict 2 . fill 9 . data 8`` and the state line
    ``⚠ 2 B would clobber source — abort on export``.

    Why: the commit re-derives the image in place and a preview that keeps
    the old plan shows the wrong conflict (base: ``conflict 1`` at ``0x8013``).
    Negative control: the window notice removed -> the band stays
    ``conflict 1`` at offset 19 -> RED."""

    async def scenario(app, pilot, log):
        await sj_scene(pilot, app, log, tmp_path)
        await save_project(pilot, app, log)
        assert [mem_at(app, a) for a in (0x8015, 0x8016)] == [0xBB, 0xCC], "the commit did not write"
        assert not window(app).has_class("hidden"), "the window closed"
        await wait_until(
            pilot,
            lambda: band_blocks(app) == BAND_TWO,
            lambda: f"the band is {band_blocks(app)!r}, expected {BAND_TWO!r}",
            timeout=FIX_WAIT,
        )
        assert state_line(app) == CLOBBER_TWO, stats_lines(app)

    drive(tmp_path, scenario)


def test_r_seg_prev_21_2_hidden_write_shows_on_the_next_open(tmp_path: Path) -> None:
    """R-SEG-PREV.21 case /2 (regression, a standing guard that passes on
    base): fixture three, Split / Join opened (join fill, pad ``0xFF``, ranges
    0 and 2 ticked) and closed with Esc; key ``6``, ``0x8013`` = ``AA``
    applied; the palette opens the window -> the band holds ``conflict 1`` at
    offset 19 (``data 8 . fill 11 . conflict 1 . fill 12 . data 8``) and the
    state line ``⚠ 1 B would clobber source — abort on export``, with the two
    ticks kept.

    Why: a write while hidden must show on the next open; the hidden notice
    must not lose the ticks or the plan. Base passes because the window
    re-syncs on open. Failure mode: a hidden notice that clears the selection
    or skips the open's re-sync, or an open that shows the cached plan."""

    async def scenario(app, pilot, log):
        await load_image(pilot, app, write_three(tmp_path / "img" / "three.s19"))
        win = await open_by_palette(pilot, app)
        await join_fill_ff(pilot, app)
        await tick_by_keys(pilot, app, [0, 2])
        await wait_until(
            pilot,
            lambda: state_line(app) == "ready — e exports",
            lambda: f"precondition: {stats_lines(app)!r}, band {band_blocks(app)!r}",
        )
        await pilot.press("escape")
        await wait_until(pilot, lambda: win.has_class("hidden"), "Esc did not close the window")
        await patch_apply(pilot, app, log, tmp_path / "docs", "d.json", [(0x8013, b"\xaa")])
        assert mem_at(app, 0x8013) == 0xAA, "the apply did not write"
        assert win.has_class("hidden"), "the window must still be closed"
        await open_by_palette(pilot, app)
        await wait_until(
            pilot,
            lambda: band_blocks(app) == BAND_ONE,
            lambda: f"the band is {band_blocks(app)!r}, expected {BAND_ONE!r}",
        )
        assert sum(size for _cls, size in band_blocks(app)[:2]) == 19
        assert state_line(app) == CLOBBER_ONE, stats_lines(app)
        assert win._sel["ranges"] == {0, 2}, f"the ticks are {win._sel['ranges']!r}"

    drive(tmp_path, scenario)


def test_r_seg_prev_22_1_preview_refresh_keeps_the_focus(tmp_path: Path) -> None:
    """R-SEG-PREV.22 case /1: as R-SEG-PREV.21/1; the open leaves ``sje_table``
    focused and ``tab`` moves the focus to the window's ``EXPORT`` button
    (``#sje_export``) before ``ctrl+s`` -> the focused widget after the dialog
    equals the one before it.

    The node first waits for the re-planned band (the refresh itself), so base
    is RED there; its focus clause is first observable with the fix.
    Negative control: the notice calls the window's open refresh, which
    focuses ``#sje_table`` -> RED. The focus starts off ``#sje_table`` because
    the open's refresh already put it there: with ``#sje_table`` focused the
    control cannot be told apart (E4 integration I-D5)."""

    async def scenario(app, pilot, log):
        await sj_scene(pilot, app, log, tmp_path)
        assert app.focused is not None and app.focused.id == "sje_table", app.focused
        await pilot.press("tab")
        await wait_until(
            pilot,
            lambda: app.focused is not None and app.focused.id == "sje_export",
            lambda: f"tab did not move the focus to #sje_export: {app.focused!r}",
        )
        before = app.focused.id
        await save_project(pilot, app, log)
        await wait_until(
            pilot,
            lambda: band_blocks(app) == BAND_TWO,
            lambda: f"the band is {band_blocks(app)!r}, expected {BAND_TWO!r}",
            timeout=FIX_WAIT,
        )
        await settle(pilot, 6)
        after = None if app.focused is None else app.focused.id
        assert after == before, f"the focus moved from #{before} to #{after}"

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# R-SEG-EXP.15 - an in-place write disarms the export confirm
# ---------------------------------------------------------------------------


async def guard_scene(pilot, app, log, tmp_path: Path):
    """Guard fixture loaded; a document ``0x3`` = ``AA`` loaded, not applied;
    Split / Join open, join fill, pad ``0xFF``, both ranges ticked, ``e``
    pressed once (armed). Returns the window."""
    await load_image(pilot, app, write_guard(tmp_path / "img" / "guard.s19"))
    doc = write_doc(app.workarea / "patches" / "g.json", [(0x3, b"\xaa")])
    await open_patch(pilot, app)
    await load_doc(pilot, app, log, doc)
    assert mem_at(app, 0x3) == 0x04, "the document must not be applied yet"
    win = await open_by_palette(pilot, app)
    await join_fill_ff(pilot, app)
    await tick_by_keys(pilot, app, [0, 1])
    await wait_until(
        pilot,
        lambda: state_line(app).startswith("⚠ GUARD") and state_line(app).endswith(WILL_ASK),
        lambda: f"precondition: state {stats_lines(app)!r}",
    )
    await pilot.press("e")
    await wait_until(
        pilot,
        lambda: state_line(app).endswith(AGAIN),
        lambda: f"precondition: the first e did not arm: {stats_lines(app)!r}",
    )
    assert joined_files(tmp_path) == [], "the arming wrote an export"
    return win


def test_r_seg_exp_15_1_save_project_commit_disarms_the_confirm(tmp_path: Path) -> None:
    """R-SEG-EXP.15 case /1: guard fixture (two 8-byte ranges at ``0x0`` and
    ``0x100000``, join fill, pad ``0xFF``, both ranges picked); a document
    ``0x00000003`` = ``AA`` loaded, not applied; Split / Join displayed; ``e``
    pressed (state line ends ``— e again to confirm``); ``ctrl+s``, Save
    project confirmed -> the state line ends ``— e will ask``; the next ``e``
    arms again (``— e again to confirm``) and 0 export files are written.

    Why: a confirm given against other bytes must not carry to the next ``e``
    (base: the arm survives the commit and the next ``e`` writes the export).
    Negative control: the notice keeps the arm -> the state line stays
    ``— e again to confirm`` -> RED."""

    async def scenario(app, pilot, log):
        win = await guard_scene(pilot, app, log, tmp_path)
        await save_project(pilot, app, log)
        assert mem_at(app, 0x3) == 0xAA, "the commit did not write"
        assert not win.has_class("hidden"), "the window closed"
        await wait_until(
            pilot,
            lambda: state_line(app).endswith(WILL_ASK),
            lambda: f"the commit did not disarm: {stats_lines(app)!r}",
            timeout=FIX_WAIT,
        )
        assert state_line(app).startswith("⚠ GUARD"), stats_lines(app)
        await pilot.press("e")
        await wait_until(
            pilot,
            lambda: state_line(app).endswith(AGAIN),
            lambda: f"the next e did not arm again: {stats_lines(app)!r}",
        )
        assert joined_files(tmp_path) == [], f"export files written: {joined_files(tmp_path)!r}"

    drive(tmp_path, scenario)


def test_r_seg_exp_15_2_hidden_write_disarms_the_confirm(tmp_path: Path) -> None:
    """R-SEG-EXP.15 case /2 (robustness): as /1 with ``e`` pressed; Esc; key
    ``6``, the document applied; the palette opens the window -> the state line
    ends ``— e will ask`` on the open; the next ``e`` arms again (``— e again
    to confirm``) and 0 export files are written.

    Why: an arm given before a write made while the window was hidden must not
    survive the reopen. Negative control: the hidden notice keeps the arm ->
    the open shows ``— e again to confirm`` -> RED."""

    async def scenario(app, pilot, log):
        win = await guard_scene(pilot, app, log, tmp_path)
        await pilot.press("escape")
        await wait_until(pilot, lambda: win.has_class("hidden"), "Esc did not close the window")
        await open_patch(pilot, app)
        await apply_loaded(pilot, app, log)
        assert mem_at(app, 0x3) == 0xAA, "the apply did not write"
        assert win.has_class("hidden"), "the window must still be closed"
        await open_by_palette(pilot, app)
        await wait_until(
            pilot,
            lambda: state_line(app).endswith(WILL_ASK),
            lambda: f"the reopen shows an armed confirm: {stats_lines(app)!r}",
            timeout=FIX_WAIT,
        )
        assert state_line(app).startswith("⚠ GUARD"), stats_lines(app)
        await pilot.press("e")
        await wait_until(
            pilot,
            lambda: state_line(app).endswith(AGAIN),
            lambda: f"the next e did not arm again: {stats_lines(app)!r}",
        )
        assert joined_files(tmp_path) == [], f"export files written: {joined_files(tmp_path)!r}"

    drive(tmp_path, scenario)


# ---------------------------------------------------------------------------
# QC-TM-10b-1 (E3 A10-12, not a coverage item) - the cost of the A2L refresh
# ---------------------------------------------------------------------------
#: The largest A2L the repo ships (E5 R-1): 37.7 MB, 220,040 tags over about
#: 1 KiB of image (the counts printed in ``evidence/inc-10b/e5c-02.txt``).
CASE06 = REPO_ROOT / "examples" / "case_06_large_nested_a2l"

#: Inside case_06's image: the second byte of the multi-byte characteristics
#: at ``0x80100004`` (a write the first byte of no such tag covers).
CASE06_WRITE = 0x80100005


@pytest.mark.serial_timing
def test_qc_tm_10b_1_a2l_refresh_cost_on_the_largest_a2l(tmp_path: Path) -> None:
    """QC-TM-10b-1: the UI-thread time of one in-place write's A2L refresh
    (``_refresh_a2l_values_after_write``) on the largest A2L the repo ships
    (case_06, re-pointed at E5 R-1) stays under ``timing_bound(1.0)``; the tag
    count is in the QC-TM label.

    The refresh is timed where the write notice calls it (the method wrapped on
    the app instance, one real apply of the complement of the byte at
    ``0x80100005`` through the Patch Editor). After the bound, the enriched
    tags must equal a full recompute over the written image (the partial
    recompute of R-1 must describe the same bytes). Negative controls: the full refresh at
    every write -> above the bound -> RED; a changed-byte test that reads only
    a tag's first byte -> the tags covering ``0x80100005`` keep their old
    values -> RED."""
    from s19_app.tui.services.a2l_service import enrich_tags_and_render

    async def scenario(app, pilot, log):
        await load_image(pilot, app, CASE06 / "firmware.s19", timeout=240.0)
        await load_a2l(pilot, app, CASE06 / "firmware.a2l", timeout=240.0)
        await wait_until(
            pilot,
            lambda: app._a2l_enriched_key is not None and len(app._a2l_enriched_tags) > 0,
            "the case_06 tags were never enriched",
            timeout=240.0,
        )
        assert hasattr(app, "_refresh_a2l_values_after_write"), (
            "the write notice has no A2L refresh to time"
        )
        real = app._refresh_a2l_values_after_write
        spans: list = []

        def timed(*args, **kwargs):
            start = time.perf_counter()
            try:
                return real(*args, **kwargs)
            finally:
                spans.append(time.perf_counter() - start)

        app._refresh_a2l_values_after_write = timed
        tags = len(app._a2l_enriched_tags)
        old = mem_at(app, CASE06_WRITE)
        assert old is not None, "0x80100005 is not in the case_06 image"
        await patch_apply(
            pilot, app, log, tmp_path / "docs", "d.json", [(CASE06_WRITE, bytes([old ^ 0xFF]))]
        )
        assert mem_at(app, CASE06_WRITE) == old ^ 0xFF, "the apply did not write"
        await wait_until(
            pilot,
            lambda: bool(spans),
            "the write notice never ran the A2L refresh",
            timeout=240.0,
        )
        elapsed = spans[0]
        print(f"QC-TM-10b-1 case_06: {tags} tags, {elapsed:.3f} s")
        assert elapsed < report_margin(
            f"QC-TM-10b-1 A2L refresh {tags} tags", elapsed, timing_bound(1.0)
        ), f"{tags} tags: {elapsed:.3f} s"
        full, _lines = enrich_tags_and_render(
            app.current_a2l_data, app.current_file.mem_map, max_tag_lines=500
        )
        differ = [
            i for i, (got, want) in enumerate(zip(app._a2l_enriched_tags, full)) if got != want
        ]
        assert len(app._a2l_enriched_tags) == len(full) and not differ, (
            f"{len(differ)} enriched tags differ from a full recompute "
            f"(first {differ[:3]}; {len(app._a2l_enriched_tags)} vs {len(full)} tags)"
        )

    drive(tmp_path, scenario)
