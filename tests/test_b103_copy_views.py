"""Batch-103 Inc1b VIEWS/GESTURES: R-COPY.1/.2/.4/.10-.15/.21/.22.

LinuxH records the OS-writer boundary without opening an OS clipboard. WinCI
uses the existing isolated clipboard and separate PowerShell reader. A Linux
writer observation is not represented as a WinCI separate-read result.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from rich.style import Style as RichStyle
from rich.text import Text
from textual import events
from textual.app import App
from textual.coordinate import Coordinate
from textual.style import Style
from textual.widgets import DataTable, TextArea
from textual.widgets.text_area import Selection

from s19_app.tui.app import S19TuiApp
from s19_app.tui.app import deps as app_deps
from s19_app.tui import os_clipboard_input as clipboard_module
from tests.support.b103_clipboard import (
    clipboard_probe,
    install_osc52_spy,
    other_program_read,
    other_program_write,
    require_isolated_clipboard,
)

SEED = "SEED-1b"
SIZE = (118, 54)
EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "case_00_public"
A2L_ROW_3 = "ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING"
MAC_ROW_3 = "Curve_ExternalAxis"
MAC_LONG = "Long record name with spaces beyond the painted column width"
WRITE_FAILED = "Clipboard write failed — copied inside the app only."
SECRET = "SECRET-SELECTION-MARKER"


@dataclass
class ClipboardLedger:
    entry: list[str] = field(default_factory=list)
    tail: list[str] = field(default_factory=list)
    tail_done: list[str] = field(default_factory=list)
    base: list[str] = field(default_factory=list)
    writes: list[str] = field(default_factory=list)
    result: bool = True

    def clear(self) -> None:
        self.entry.clear()
        self.tail.clear()
        self.tail_done.clear()
        self.base.clear()
        self.writes.clear()


@pytest.fixture(autouse=True)
def clipboard(monkeypatch: pytest.MonkeyPatch):
    """Isolate every OS clipboard edge before the application starts."""
    ledger = ClipboardLedger()
    if sys.platform == "win32":
        require_isolated_clipboard("windows")
        usable, detail = clipboard_probe()
        if not usable:
            pytest.skip(f"runner clipboard unusable: {detail}")
    else:
        assert not os.environ.get("DISPLAY"), "LinuxH requires DISPLAY unset"
        assert not os.environ.get("WAYLAND_DISPLAY"), "LinuxH requires WAYLAND_DISPLAY unset"

    real_write = clipboard_module.write_os_clipboard
    original_entry = S19TuiApp.copy_to_clipboard
    original_base = App.copy_to_clipboard
    original_tail = clipboard_module._mirror_and_write_os_clipboard

    def write(text, strategies=None):
        ledger.writes.append(text)
        if sys.platform == "win32":
            return real_write(text, strategies=strategies)
        return ledger.result

    def entry(app, text):
        ledger.entry.append(text)
        return original_entry(app, text)

    def base(app, text):
        ledger.base.append(text)
        return original_base(app, text)

    async def tail(app, text):
        ledger.tail.append(text)
        try:
            return await original_tail(app, text)
        finally:
            ledger.tail_done.append(text)

    monkeypatch.setattr(clipboard_module, "write_os_clipboard", write)
    monkeypatch.setattr(clipboard_module, "read_os_clipboard", lambda strategies=None: None)
    monkeypatch.setattr(clipboard_module, "_prime_tk_root", lambda: None, raising=False)
    monkeypatch.setattr(S19TuiApp, "copy_to_clipboard", entry)
    monkeypatch.setattr(App, "copy_to_clipboard", base)
    monkeypatch.setattr(clipboard_module, "_mirror_and_write_os_clipboard", tail)
    # The app's copy entry calls the tail through its deps seam (s19_app/tui/app/deps.py).
    monkeypatch.setattr(app_deps, "_mirror_and_write_os_clipboard", tail)
    return ledger


@dataclass
class Session:
    app: S19TuiApp
    pilot: object
    osc52: list[str]
    clipboard: ClipboardLedger


async def _settle(pilot, count: int = 6) -> None:
    for _ in range(count):
        await pilot.pause(0.02)


async def _wait(pilot, predicate, label: str) -> None:
    for _ in range(1000):
        if predicate():
            return
        await pilot.pause(0.02)
    raise AssertionError(f"fixture timeout: {label}")


async def _wait_copy_tail(session: Session) -> None:
    if not session.clipboard.entry:
        return
    await _wait(
        session.pilot,
        lambda: bool(session.clipboard.tail_done),
        "clipboard tail completion",
    )
    await _settle(session.pilot, 2)


async def _load(app, pilot, tmp_path: Path, name: str) -> None:
    target = tmp_path / name
    shutil.copyfile(EXAMPLES / name, target)
    if name.endswith(".a2l"):
        app.load_a2l_from_path(target)
        await _wait(pilot, lambda: bool(getattr(app, "current_a2l_data", None)), name)
    else:
        app.load_from_path(target)
        if name.endswith(".mac"):
            await _wait(
                pilot,
                lambda: getattr(app.current_file, "mac_path", None) is not None,
                name,
            )
        else:
            await _wait(pilot, lambda: app.current_file is not None, name)
    await _settle(pilot)


@asynccontextmanager
async def _session(tmp_path: Path, clipboard: ClipboardLedger, needs: tuple[str, ...]):
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=SIZE, notifications=True) as pilot:
        await _settle(pilot)
        osc52 = install_osc52_spy(app)
        if "s19" in needs or "a2l" in needs or "mac" in needs or "all" in needs:
            await _load(app, pilot, tmp_path, "prg.s19")
        if "mac" in needs or "all" in needs:
            await _load(app, pilot, tmp_path, "synthetic_update_test1.mac")
        if "a2l" in needs or "all" in needs:
            await _load(app, pilot, tmp_path, "ASAP2_Demo_V171.a2l")
        yield Session(app, pilot, osc52, clipboard)


def _arm(session: Session) -> None:
    session.app._clipboard = SEED
    session.app.clear_notifications()
    session.clipboard.clear()
    session.osc52.clear()
    if sys.platform == "win32":
        other_program_write(SEED)


async def _activate(session: Session, key: str) -> None:
    session.app.action_show_screen(key)
    await _settle(session.pilot)


async def _show_json(session: Session) -> TextArea:
    await _activate(session, "patch")
    assert await session.pilot.click("#patch_tab_json")
    await _wait(
        session.pilot,
        lambda: session.app.query_one("#patch_json_view").region.area > 0,
        "visible #patch_json_view",
    )
    return session.app.query_one("#patch_json_view", TextArea)


async def _show_help(session: Session):
    await _activate(session, "workspace")
    await session.pilot.press("question_mark")
    await _wait(
        session.pilot,
        lambda: bool(session.app.screen.query("#window_help_body")),
        "Workspace help",
    )
    return session.app.screen.query_one("#window_help_body")


def _notices(app: S19TuiApp) -> list[tuple[str, str]]:
    return [(str(note.message), note.severity) for note in app._notifications]


def _assert_os(expected: str) -> None:
    if sys.platform == "win32":
        assert other_program_read() == expected


def _assert_no_os_write(session: Session) -> None:
    assert session.clipboard.writes == []
    if sys.platform == "win32":
        assert other_program_read() == SEED


def _assert_no_copy(session: Session) -> None:
    assert session.clipboard.entry == []
    assert session.clipboard.tail == []
    assert session.clipboard.base == []
    assert session.osc52 == []
    _assert_no_os_write(session)
    assert session.app.clipboard == SEED


def _assert_single_copy(session: Session, expected: str, *, notice: bool = True) -> None:
    assert session.clipboard.entry == [expected]
    assert session.clipboard.tail == [expected]
    assert session.clipboard.base == [expected]
    assert session.clipboard.writes == [expected]
    assert session.osc52 == [expected]
    assert session.app.clipboard == expected
    _assert_os(expected)
    if notice:
        copy_notices = [m for m, _ in _notices(session.app) if m.startswith("Copied")]
        assert len(copy_notices) == 1, copy_notices


def _assert_writer(session: Session, expected: str) -> None:
    assert session.clipboard.writes == [expected]
    _assert_os(expected)


def _mouse(session: Session, cls, widget, offset: tuple[int, int], button: int = 3):
    region = widget.region
    x = region.x + offset[0]
    y = region.y + offset[1]
    return cls(widget, x, y, 0, 0, button, False, False, False, x, y, None)


def _screen_point(widget, offset: tuple[int, int]) -> tuple[int, int]:
    return widget.region.x + offset[0], widget.region.y + offset[1]


async def _right_click(
    session: Session,
    widget,
    offset: tuple[int, int],
    *,
    out_of_bounds: bool | None = None,
    expected_row: int | None = None,
) -> None:
    restore = None
    if out_of_bounds is not None:
        screen = session.app.screen
        original = screen.get_style_at
        target = _screen_point(widget, offset)
        original_meta = dict(original(*target).meta)
        if expected_row is not None:
            assert original_meta.get("row") == expected_row, original_meta
            assert original_meta.get("column", -1) >= 0, original_meta

        def controlled(x: int, y: int):
            style = original(x, y)
            if (x, y) != target:
                return style
            meta = dict(style.meta)
            meta["out_of_bounds"] = out_of_bounds
            return Style.from_rich_style(RichStyle(meta=meta))

        screen.get_style_at = controlled
        restore = original
    try:
        session.app.post_message(_mouse(session, events.MouseDown, widget, offset))
        session.app.post_message(_mouse(session, events.MouseUp, widget, offset))
        await _settle(session.pilot)
        await _wait_copy_tail(session)
    finally:
        if restore is not None:
            session.app.screen.get_style_at = restore


async def _right_drag(
    session: Session,
    widget,
    start,
    middle,
    *,
    return_to_start: bool,
    forwarded: bool = False,
):
    session.app.post_message(_mouse(session, events.MouseDown, widget, start))
    move = _mouse(session, events.MouseMove, widget, middle)
    if forwarded:
        move._set_forwarded()
    session.app.post_message(move)
    if return_to_start:
        move = _mouse(session, events.MouseMove, widget, start)
        if forwarded:
            move._set_forwarded()
        session.app.post_message(move)
        end = start
    else:
        end = middle
    session.app.post_message(_mouse(session, events.MouseUp, widget, end))
    await _settle(session.pilot)
    await _wait_copy_tail(session)


async def _drag(session: Session, selector: str, start, end) -> None:
    session.app.screen.clear_selection()
    await session.pilot.pause()
    await session.pilot.mouse_down(selector, offset=start)
    await session.pilot.hover(selector, offset=end)
    await session.pilot.mouse_up(selector, offset=end)
    await _settle(session.pilot)


def _selection(session: Session, lines: int) -> str:
    selected = session.app.screen.get_selected_text()
    assert selected, "the drag must materialize a selection"
    assert len(selected.splitlines()) == lines, repr(selected)
    return selected


def _a2l_name(app: S19TuiApp, row: int) -> str:
    tag = app._a2l_row_key_to_tag[f"a2l:{row}"]
    name = tag.get("name") if isinstance(tag, dict) else tag.name
    assert isinstance(name, str) and name
    return name


def _table(session: Session, selector: str) -> DataTable:
    table = session.app.query_one(selector, DataTable)
    assert table.row_count >= 5 if selector == "#a2l_tags_list" else table.row_count >= 3
    return table


def _row_offset(table: DataTable, row: int, x: int = 4) -> tuple[int, int]:
    return x, table.header_height + row


def _record_row_selected(app: S19TuiApp) -> list:
    original = app.on_data_table_row_selected
    records = []

    def record(event):
        records.append(event)
        return original(event)

    app.on_data_table_row_selected = record
    return records


def _first_line(app: S19TuiApp, selector: str) -> str:
    lines = str(app.query_one(selector).render()).splitlines()
    assert lines and lines[0]
    return lines[0]


async def _make_view_selection(session: Session, source: str) -> str:
    if source == "hex":
        await _activate(session, "workspace")
        await _drag(session, "#hex_view", (2, 1), (40, 3))
        selected = _selection(session, 3)
        assert len(set(selected.splitlines())) == 3
        return selected
    if source == "stats":
        await _activate(session, "workspace")
        widget = session.app.query_one("#ws_stats")
        await _drag(session, "#ws_stats", (0, 0), (max(2, widget.region.width - 2), 4))
        return _selection(session, 5)
    if source == "summary":
        await _activate(session, "a2l")
        await _drag(session, "#a2l_tags_summary", (0, 0), (60, 0))
        selected = _selection(session, 1)
        assert "Page 1/1 | tags 1-118 / 118" in selected
        return selected
    if source == "detail":
        await _activate(session, "a2l")
        table = _table(session, "#a2l_tags_list")
        table.focus()
        table.move_cursor(row=1)
        await _settle(session.pilot)
        table.move_cursor(row=0)
        await _settle(session.pilot)
        assert _a2l_name(session.app, 0) in str(session.app.query_one("#a2l_detail_card").render())
        widget = session.app.query_one("#a2l_detail_card")
        await _drag(session, "#a2l_detail_card", (0, 1), (max(2, widget.region.width - 2), 3))
        # TQR-04: keep the real drag unmodified; the two-line driver arm is reported partial.
        selected = _selection(session, 5)
        assert len(set(selected.splitlines())) == 5
        return selected
    if source == "json":
        widget = await _show_json(session)
        assert await session.pilot.click(widget, offset=(0, 0))
        widget.selection = Selection((0, 0), (0, 0))
        widget.focus()
        await session.pilot.press("shift+down", "shift+down")
        await _settle(session.pilot)
        selected = widget.selected_text
        assert selected and len(selected.splitlines()) == 2, repr(selected)
        return selected
    if source == "help":
        widget = await _show_help(session)
        await _drag(session, "#window_help_body", (0, 0), (max(2, widget.region.width - 2), 4))
        selected = session.app.screen.get_selected_text()
        assert selected and len([line for line in selected.splitlines() if line]) == 2, repr(selected)
        return selected
    if source == "cross":
        await _activate(session, "workspace")
        stats_first = str(session.app.query_one("#ws_stats").render()).splitlines()[0].strip()
        a2l_first = str(session.app.query_one("#a2l_view").render()).splitlines()[0].strip()
        assert stats_first and a2l_first and stats_first != a2l_first
        session.app.screen.clear_selection()
        await session.pilot.pause()
        await session.pilot.mouse_down("#ws_stats", offset=(0, 0))
        await session.pilot.hover("#a2l_view", offset=(30, 0))
        await session.pilot.mouse_up("#a2l_view", offset=(30, 0))
        await _settle(session.pilot)
        selected = session.app.screen.get_selected_text()
        assert selected and selected != stats_first and selected != a2l_first
        assert selected.index(stats_first) < selected.index(a2l_first), repr(selected)
        return selected
    raise AssertionError(source)


def _right_target(source: str):
    return {
        "hex": ("#hex_view", (10, 2)),
        "stats": ("#ws_stats", (5, 2)),
        "detail": ("#a2l_detail_card", (5, 1)),
        "json": ("#patch_json_view", (2, 0)),
        "help": ("#window_help_body", (5, 0)),
        "cross": ("#a2l_view", (5, 0)),
    }[source]


@pytest.mark.parametrize(
    "source",
    ["hex", "stats", "summary", "detail", "json", "help"],
    ids=[f"R-COPY.1/{i}" for i in range(1, 7)],
)
def test_r_copy_1_ctrl_c_writes_each_view(tmp_path: Path, clipboard, source: str) -> None:
    needs = ("a2l",) if source in {"summary", "detail"} else ("s19",)

    async def drive():
        async with _session(tmp_path, clipboard, needs) as session:
            expected = await _make_view_selection(session, source)
            top = session.app.screen
            _arm(session)
            await session.pilot.press("ctrl+c")
            await _settle(session.pilot)
            _assert_writer(session, expected)
            if source == "help":
                assert session.app.screen is top

    asyncio.run(drive())


@pytest.mark.parametrize("case", [1, 2, 3, 4], ids=[f"R-COPY.2/{i}" for i in range(1, 5)])
def test_r_copy_2_app_clipboard(tmp_path: Path, clipboard, case: int) -> None:
    if case == 4 and sys.platform == "win32":
        pytest.skip("Linux-only existing failing-writer arm")

    async def drive():
        needs = ("a2l",) if case >= 3 else ("s19",)
        async with _session(tmp_path, clipboard, needs) as session:
            if case == 1:
                expected = await _make_view_selection(session, "hex")
                _arm(session)
                await session.pilot.press("ctrl+c")
            elif case == 2:
                expected = await _make_view_selection(session, "hex")
                _arm(session)
                await _right_click(session, session.app.query_one("#hex_view"), (10, 2))
            else:
                await _activate(session, "a2l")
                table = _table(session, "#a2l_tags_list")
                assert _a2l_name(session.app, 2) == A2L_ROW_3
                expected = A2L_ROW_3
                clipboard.result = case != 4
                _arm(session)
                await _right_click(
                    session,
                    table,
                    _row_offset(table, 2),
                    out_of_bounds=False,
                    expected_row=2,
                )
            await _settle(session.pilot)
            assert session.app.clipboard == expected
            assert session.clipboard.base == [expected]
            assert session.osc52 == [expected]
            assert session.clipboard.writes == [expected]
            if case == 4:
                assert _notices(session.app) == [(WRITE_FAILED, "warning")]

    asyncio.run(drive())


@pytest.mark.parametrize("case", [1, 2, 3], ids=[f"R-COPY.4/{i}" for i in range(1, 4)])
def test_r_copy_4_full_row_names(tmp_path: Path, clipboard, case: int) -> None:
    async def drive():
        async with _session(tmp_path, clipboard, (("a2l",) if case != 2 else ("mac",))) as session:
            if case == 1:
                await _activate(session, "a2l")
                table = _table(session, "#a2l_tags_list")
                assert table.cursor_row == 0
                assert _a2l_name(session.app, 2) == A2L_ROW_3
                expected = A2L_ROW_3
                _arm(session)
                await _right_click(session, table, _row_offset(table, 2), out_of_bounds=False, expected_row=2)
                _assert_writer(session, expected)
            elif case == 3:
                await _activate(session, "a2l")
                table = _table(session, "#a2l_tags_list")
                table.move_cursor(row=1)
                await _settle(session.pilot)
                expected = _a2l_name(session.app, 4)
                assert expected != _a2l_name(session.app, 1)
                _arm(session)
                await _right_click(session, table, _row_offset(table, 4), out_of_bounds=False, expected_row=4)
                _assert_writer(session, expected)
            else:
                await _activate(session, "mac")
                table = _table(session, "#mac_records_list")
                cell = table.get_row_at(2)[0]
                assert isinstance(cell, Text) and cell.plain == "⚠ Curve_ExternalAxis"
                _arm(session)
                await _right_click(session, table, _row_offset(table, 2), out_of_bounds=False, expected_row=2)
                _assert_writer(session, MAC_ROW_3)

                table.update_cell_at(Coordinate(2, 0), Text("⚠ " + MAC_LONG))
                changed = table.get_row_at(2)[0]
                assert isinstance(changed, Text) and changed.plain == "⚠ " + MAC_LONG
                _arm(session)
                await _right_click(session, table, _row_offset(table, 2), out_of_bounds=False, expected_row=2)
                _assert_writer(session, MAC_LONG)

    asyncio.run(drive())


@pytest.mark.parametrize("case", [1, 2, 3], ids=[f"R-COPY.10/{i}" for i in range(1, 4)])
def test_r_copy_10_one_osc52_request(tmp_path: Path, clipboard, case: int) -> None:
    async def drive():
        async with _session(tmp_path, clipboard, (("a2l",) if case == 3 else ("s19",))) as session:
            if case in {1, 2}:
                expected = await _make_view_selection(session, "hex")
                _arm(session)
                if case == 1:
                    await session.pilot.press("ctrl+c")
                else:
                    await _right_click(session, session.app.query_one("#hex_view"), (10, 2))
            else:
                await _activate(session, "a2l")
                table = _table(session, "#a2l_tags_list")
                expected = A2L_ROW_3
                assert _a2l_name(session.app, 2) == expected
                _arm(session)
                await _right_click(session, table, _row_offset(table, 2), out_of_bounds=False, expected_row=2)
            await _settle(session.pilot)
            assert session.osc52 == [expected]

    asyncio.run(drive())


@pytest.mark.parametrize("case", [1, 2, 3, 4, 5], ids=[f"R-COPY.11/{i}" for i in range(1, 6)])
def test_r_copy_11_selection_and_highlight_do_not_copy(tmp_path: Path, clipboard, case: int) -> None:
    async def drive():
        needs = ("a2l",) if case in {2, 4} else ("s19",)
        async with _session(tmp_path, clipboard, needs) as session:
            if case == 1:
                await _activate(session, "workspace")
                _arm(session)
                await _drag(session, "#hex_view", (2, 1), (40, 3))
                _selection(session, 3)
            elif case == 2:
                await _activate(session, "a2l")
                table = _table(session, "#a2l_tags_list")
                table.focus()
                _arm(session)
                await session.pilot.press("down", "down", "down")
                await _settle(session.pilot)
                assert table.cursor_row == 3
            elif case == 3:
                view = await _show_json(session)
                view.focus()
                _arm(session)
                await session.pilot.press("f7")
                await _settle(session.pilot)
                assert view.selected_text
            elif case == 4:
                await _activate(session, "a2l")
                table = _table(session, "#a2l_tags_list")
                _arm(session)
                assert await session.pilot.click(table, offset=_row_offset(table, 4), button=1)
                await _settle(session.pilot)
                assert table.cursor_row == 4
            else:
                for forwarded in (False, True):
                    await _activate(session, "workspace")
                    view = session.app.query_one("#hex_view")
                    view.update(f"{SECRET} row 0\nsecond row\nthird row")
                    await _drag(session, "#hex_view", (0, 0), (12, 2))
                    assert SECRET in _selection(session, 3)
                    _arm(session)
                    await _right_drag(
                        session,
                        view,
                        (4, 1),
                        (20, 2),
                        return_to_start=False,
                        forwarded=forwarded,
                    )
                    _assert_no_copy(session)
                    assert _notices(session.app) == []
            _assert_no_copy(session)

    asyncio.run(drive())


@pytest.mark.parametrize(
    "source",
    ["hex", "stats", "detail", "json", "help", "cross"],
    ids=[f"R-COPY.12/{i}" for i in range(1, 7)],
)
def test_r_copy_12_right_click_selection(tmp_path: Path, clipboard, source: str) -> None:
    async def drive():
        needs = ("a2l",) if source == "detail" else ("s19",)
        async with _session(tmp_path, clipboard, needs) as session:
            expected = await _make_view_selection(session, source)
            selector, offset = _right_target(source)
            _arm(session)
            await _right_click(session, session.app.screen.query_one(selector), offset)
            _assert_writer(session, expected)

    asyncio.run(drive())


def test_r_copy_12_7_back_to_back_and_reentry(tmp_path: Path, clipboard) -> None:
    """R-COPY.12/7, including the graph's replacement/replay control."""
    async def drive():
        async with _session(tmp_path, clipboard, ("s19",)) as session:
            expected = await _make_view_selection(session, "hex")
            view = session.app.query_one("#hex_view")
            _arm(session)
            session.app.post_message(_mouse(session, events.MouseDown, view, (5, 1)))
            session.app.post_message(_mouse(session, events.MouseDown, view, (10, 2)))
            session.app.post_message(_mouse(session, events.MouseUp, view, (5, 1)))
            await _settle(session.pilot)
            _assert_no_copy(session)

            assert await _make_view_selection(session, "hex") == expected
            _arm(session)
            await _right_click(session, view, (10, 2))
            _assert_single_copy(session, expected)
            writes = list(clipboard.writes)
            osc52 = list(session.osc52)
            session.app.post_message(_mouse(session, events.MouseUp, view, (10, 2)))
            await _settle(session.pilot)
            assert clipboard.writes == writes
            assert session.osc52 == osc52

    asyncio.run(drive())


def test_r_copy_12_8_positive_bounds_and_cardinality(tmp_path: Path, clipboard) -> None:
    """R-COPY.12/8: hex, A2L and MAC positive out_of_bounds controls."""
    async def drive():
        async with _session(tmp_path, clipboard, ("all",)) as session:
            expected = await _make_view_selection(session, "hex")
            _arm(session)
            await _right_click(
                session,
                session.app.query_one("#hex_view"),
                (10, 2),
                out_of_bounds=False,
            )
            _assert_single_copy(session, expected)

            for key, selector, wanted in (
                ("a2l", "#a2l_tags_list", A2L_ROW_3),
                ("mac", "#mac_records_list", MAC_ROW_3),
            ):
                await _activate(session, key)
                table = _table(session, selector)
                selected = _record_row_selected(session.app)
                _arm(session)
                await _right_click(
                    session,
                    table,
                    _row_offset(table, 2),
                    out_of_bounds=False,
                    expected_row=2,
                )
                _assert_single_copy(session, wanted)
                assert table.cursor_row == 2
                assert selected == []

    asyncio.run(drive())


async def _padding_arm(session: Session, key: str, selector: str, hex_selectors: tuple[str, ...]):
    await _activate(session, key)
    table = _table(session, selector)
    table.move_cursor(row=0)
    await _settle(session.pilot)
    before_cursor = table.cursor_row
    before_hex = tuple(_first_line(session.app, item) for item in hex_selectors)
    selected = _record_row_selected(session.app)
    _arm(session)
    await _right_click(
        session,
        table,
        _row_offset(table, 2),
        out_of_bounds=True,
        expected_row=2,
    )
    return table, before_cursor, before_hex, selected, hex_selectors


async def _empty_gesture(session: Session, case: int):
    states = []
    if case == 1:
        await _activate(session, "workspace")
        session.app.screen.clear_selection()
        _arm(session)
        await _right_click(session, session.app.query_one("#hex_view"), (10, 2))
    elif case == 2:
        view = await _show_json(session)
        view.selection = Selection((0, 0), (0, 0))
        _arm(session)
        await _right_click(session, view, (2, 0))
    elif case == 3:
        view = await _show_help(session)
        session.app.screen.clear_selection()
        _arm(session)
        await _right_click(session, view, (5, 0))
    elif case == 4:
        await _make_view_selection(session, "hex")
        _arm(session)
        await _right_click(session, session.app.query_one("#ws_stats"), (5, 2))
    elif case == 5:
        await _activate(session, "a2l")
        table = _table(session, "#a2l_tags_list")
        _arm(session)
        await _right_click(session, table, (4, 0))
    elif case == 6:
        await _activate(session, "a2l")
        table = session.app.query_one("#a2l_tags_list", DataTable)
        assert table.row_count == 0
        _arm(session)
        await _right_click(session, table, _row_offset(table, 0))
    elif case in {7, 8}:
        for forwarded in (False, True):
            await _activate(session, "workspace")
            view = session.app.query_one("#hex_view")
            view.update(f"{SECRET} row 0\nsecond row\nthird row")
            await _drag(session, "#hex_view", (0, 0), (12, 2))
            assert SECRET in _selection(session, 3)
            _arm(session)
            await _right_drag(
                session,
                view,
                (4, 1),
                (20, 2),
                return_to_start=case == 8,
                forwarded=forwarded,
            )
            states.append((None, list(session.osc52), list(clipboard_payloads(session)), _notices(session.app)))
        return states
    else:
        for key, selector, hex_views in (
            ("a2l", "#a2l_tags_list", ("#hex_view", "#alt_hex_view")),
            ("mac", "#mac_records_list", ("#mac_hex_view",)),
        ):
            before = await _padding_arm(session, key, selector, hex_views)
            states.append((before, list(session.osc52), list(clipboard_payloads(session)), _notices(session.app)))
        return states
    states.append((None, list(session.osc52), list(clipboard_payloads(session)), _notices(session.app)))
    return states


def clipboard_payloads(session: Session) -> tuple[list[str], list[str], list[str], list[str], str]:
    return (
        list(session.clipboard.entry),
        list(session.clipboard.tail),
        list(session.clipboard.base),
        list(session.clipboard.writes),
        session.app.clipboard,
    )


@pytest.mark.parametrize("case", list(range(1, 10)), ids=[f"R-COPY.13/{i}" for i in range(1, 10)])
def test_r_copy_13_empty_and_cancelled_gestures(tmp_path: Path, clipboard, case: int) -> None:
    needs = ("all",) if case == 9 else (("a2l",) if case == 5 else ("s19",))

    async def drive():
        async with _session(tmp_path, clipboard, needs) as session:
            states = await _empty_gesture(session, case)
            for before, osc52, payloads, notices in states:
                entry, tail, base, writes, app_clipboard = payloads
                assert entry == tail == base == writes == []
                assert osc52 == []
                assert app_clipboard == SEED
                assert notices == []
                if before is not None:
                    table, cursor, hex_lines, selected, selectors = before
                    assert table.cursor_row == cursor
                    assert tuple(_first_line(session.app, item) for item in selectors) == hex_lines
                    assert selected == []
            if sys.platform == "win32":
                assert other_program_read() == SEED

    asyncio.run(drive())


@pytest.mark.parametrize("case", list(range(1, 10)), ids=[f"R-COPY.14/{i}" for i in range(1, 10)])
def test_r_copy_14_empty_and_cancelled_gestures_have_no_notice(tmp_path: Path, clipboard, case: int) -> None:
    needs = ("all",) if case == 9 else (("a2l",) if case == 5 else ("s19",))

    async def drive():
        async with _session(tmp_path, clipboard, needs) as session:
            states = await _empty_gesture(session, case)
            for _before, _osc52, _payloads, notices in states:
                assert notices == []

    asyncio.run(drive())


@pytest.mark.parametrize("source", ["hex", "stats", "json"], ids=[f"R-COPY.15/{i}" for i in range(1, 4)])
def test_r_copy_15_right_click_clears_selection(tmp_path: Path, clipboard, source: str) -> None:
    async def drive():
        async with _session(tmp_path, clipboard, ("s19",)) as session:
            expected = await _make_view_selection(session, source)
            selector, offset = _right_target(source)
            _arm(session)
            await _right_click(session, session.app.screen.query_one(selector), offset)
            _assert_single_copy(session, expected)
            if source == "json":
                assert session.app.query_one("#patch_json_view", TextArea).selected_text == ""
            else:
                assert not session.app.screen.get_selected_text()

    asyncio.run(drive())


@pytest.mark.parametrize("key", ["a2l", "mac"], ids=["R-COPY.21/1", "R-COPY.21/2"])
def test_r_copy_21_valid_right_click_highlights_without_selection(tmp_path: Path, clipboard, key: str) -> None:
    async def drive():
        async with _session(tmp_path, clipboard, (key,)) as session:
            await _activate(session, key)
            selector = "#a2l_tags_list" if key == "a2l" else "#mac_records_list"
            table = _table(session, selector)
            row = 4 if key == "a2l" else 2
            expected_name = _a2l_name(session.app, row) if key == "a2l" else None
            selected = _record_row_selected(session.app)
            _arm(session)
            await _right_click(session, table, _row_offset(table, row), out_of_bounds=False, expected_row=row)
            assert table.cursor_row == row
            assert selected == []
            if expected_name is not None:
                assert expected_name in str(session.app.query_one("#a2l_detail_card").render())

    asyncio.run(drive())


@pytest.mark.parametrize("key", ["a2l", "mac"], ids=["R-COPY.22/1", "R-COPY.22/2"])
def test_r_copy_22_right_click_does_not_jump_hex(tmp_path: Path, clipboard, key: str) -> None:
    async def drive():
        async with _session(tmp_path, clipboard, (key,)) as session:
            await _activate(session, key)
            selector = "#a2l_tags_list" if key == "a2l" else "#mac_records_list"
            table = _table(session, selector)
            table.move_cursor(row=2)
            await _settle(session.pilot)
            hex_selectors = ("#hex_view", "#alt_hex_view") if key == "a2l" else ("#mac_hex_view",)
            before = tuple(_first_line(session.app, item) for item in hex_selectors)
            selected = _record_row_selected(session.app)
            _arm(session)
            await _right_click(session, table, _row_offset(table, 2), out_of_bounds=False, expected_row=2)
            assert tuple(_first_line(session.app, item) for item in hex_selectors) == before
            assert selected == []

    asyncio.run(drive())
