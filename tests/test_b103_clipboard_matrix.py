"""Batch-103 Inc 1a clipboard matrix and walk (G-T3).

Summary:
    The copy→paste matrix (AT-I1a-1 … 8, 12 … 27: two copy ways × three paste
    routes × four class pairs) and the every-window walk (R-TUI-044.1/1-17,
    R-PASTE.18/1-7), each place a Ctrl+C/Ctrl+V round trip and a right-click
    round trip (R-PASTE.19/2, R-PASTE.33/2). Sources: Box A (P1) and Box M
    (P2); targets: Box A' (``#diff_path_a``) and Box M' (``#sje_manual``).
    Route 1 is Ctrl+V, route 2 the terminal paste, route 3 the right-click in
    the cleared target; copy way C1 is Ctrl+C, C2 the right-click on the
    selection.

    The LinuxH arms run now through the app clipboard and the decoded OSC 52
    request (the route-2 source a terminal that honours OSC 52 would use);
    the WinCI arms use the OS clipboard and are collected by the Windows job
    (R-PASTE.20). AT-I1a-9 is WinCI-only; AT-I1a-10 / -11 are operator-run.

Dependencies:
    Uses:
        - ``tests.support.b103_clipboard`` (payloads, helpers)
        - ``tests.b97_fixtures`` (Flow Builder / Execution walk places)
    Used by:
        - the Inc 1a E4 matrix/walk run
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from textual.widgets import Input, TextArea

from s19_app.tui.app import S19TuiApp
from tests.support.b103_clipboard import (
    P1,
    P2,
    _box,
    _set_box,
    install_osc52_spy,
    right_click_app_route,
    terminal_paste,
)

_LINUXH = sys.platform != "win32"

# The class-pair sources/targets: (source_screen, source_id, target_screen,
# target_id, target_kind). Box A = a2l filter, Box M = patch paste buffer,
# Box A' = diff path, Box M' = split/join/export manual ranges.
_A = ("a2l", "#a2l_tags_filter_input", "input")
_M = ("patch", "#patch_paste_text", "textarea")
_A_PRIME = ("diff", "#diff_path_a", "input")
_M_PRIME = ("sje", "#sje_manual", "textarea")


async def _app_with(tmp_path: Path):
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        yield app, pilot


def _screen_for(place: tuple) -> str:
    return place[0]


async def _activate(app, pilot, screen_key: str) -> None:
    app.action_show_screen(screen_key)
    for _ in range(4):
        await pilot.pause()


async def _source_widget(app, pilot, source: tuple):
    await _activate(app, pilot, source[0])
    if source[2] == "input":
        return app.query_one(source[1], Input)
    return app.query_one(source[1], TextArea)


async def _target_widget(app, pilot, target: tuple):
    if target[0] == "sje":
        app.action_open_split_join_export()
    else:
        await _activate(app, pilot, target[0])
    if target[2] == "input":
        return app.query_one(target[1], Input)
    return app.query_one(target[1], TextArea)


def _payload_for(source: tuple, *, right: bool = False) -> str:
    base = P1 if source[2] == "input" else P2
    return base


def _expected_for(source: tuple, target: tuple, payload: str) -> str:
    if target[2] == "input" and source[2] == "textarea":
        return payload.splitlines()[0]  # the first line
    return payload


async def _select(widget: object) -> None:
    if isinstance(widget, TextArea):
        widget.select_all()
    else:
        widget.selection = (0, len(widget.value or ""))


async def _clear(widget: object) -> None:
    _set_box(widget, "")


# ---------------------------------------------------------------------------
# The 24-cell matrix, parametrized
# ---------------------------------------------------------------------------


_MATRIX_CELLS = []
for _i, (source, target) in enumerate(
    [(_A, _A_PRIME), (_A, _M_PRIME), (_M, _A_PRIME), (_M, _M_PRIME)]
):
    for _route in ("ctrl_v", "terminal", "right_click"):
        for _copy in ("ctrl_c", "right_click"):
            _case = {
                # source -> target, route, copy way
                "source": source,
                "target": target,
                "route": _route,
                "copy": _copy,
            }
            _MATRIX_CELLS.append(_case)


def _cell_id(cell: dict) -> str:
    s = "A" if cell["source"][2] == "input" else "M"
    t = "A" if cell["target"][2] == "input" else "M"
    return f"{s}->{t}_{cell['copy']}_{cell['route']}"


@pytest.mark.parametrize("cell", _MATRIX_CELLS, ids=[_cell_id(c) for c in _MATRIX_CELLS])
def test_at_i1a_matrix_copy_then_paste(tmp_path: Path, cell: dict) -> None:
    """One matrix cell (AT-I1a-1 … 8, 12 … 27, LinuxH arm): copy from the
    source by C1/C2, paste into the target by route 1/2/3, assert the text."""
    if not _LINUXH:
        pytest.skip("Windows only")

    async def _drive() -> str:
        async for app, pilot in _app_with(tmp_path):
            osc = install_osc52_spy(app)
            source = await _source_widget(app, pilot, cell["source"])
            payload = _payload_for(cell["source"])
            _set_box(source, payload)
            await _select(source)
            source.focus()
            await pilot.pause()
            # Copy
            if cell["copy"] == "ctrl_c":
                await pilot.press("ctrl+c")
            else:
                await right_click_app_route(app, source)
            await pilot.pause()
            await pilot.pause()
            # Target
            target = await _target_widget(app, pilot, cell["target"])
            await _clear(target)
            target.focus()
            await pilot.pause()
            if cell["route"] == "ctrl_v":
                await pilot.press("ctrl+v")
            elif cell["route"] == "terminal":
                if osc:
                    await terminal_paste(app, osc[-1])
                else:
                    await terminal_paste(app, app.clipboard)
            else:
                await right_click_app_route(app, target)
            await pilot.pause()
            await pilot.pause()
            return _box(target)

    result = asyncio.run(_drive())
    payload = _payload_for(cell["source"])
    expected = _expected_for(cell["source"], cell["target"], payload)
    assert result == expected, (cell["source"], cell["target"], cell["copy"], cell["route"], result)


# ---------------------------------------------------------------------------
# The walk (one round trip per place). LinuxH arm.
# ---------------------------------------------------------------------------


def _single_line_places():
    """(screen_key, widget_id, needs_project) for R-TUI-044.1/1-17."""
    return [
        ("workspace", "#search_input", False),
        ("a2l", "#a2l_tags_filter_input", False),
        ("mac", "#mac_search_input", False),
        ("patch", "#patch_entry_address_input", False),
        ("diff", "#diff_path_a", False),
        ("crc_designer", "#crc_field_width", False),
    ]


@pytest.mark.parametrize(
    "place", _single_line_places(), ids=[p[0] for p in _single_line_places()]
)
def test_r_tui_044_1_walk_single_line_round_trip(tmp_path: Path, place: tuple) -> None:
    """R-TUI-044.1/1-6,9 (LinuxH): a Ctrl+C/Ctrl+V and a right-click round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")
    screen_key, widget_id, _ = place

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            await _activate(app, pilot, screen_key)
            widget = app.query_one(widget_id, Input)
            widget.focus()
            await pilot.pause()
            # Ctrl round trip
            widget.value = f"W1-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            ctrl_value = widget.value
            # Right-click round trip
            widget.value = f"R1-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await right_click_app_route(app, widget)
            await pilot.pause()
            rc_copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await right_click_app_route(app, widget)
            await pilot.pause()
            return copied, ctrl_value, rc_copied, widget.value

    copied, ctrl_value, rc_copied, rc_value = asyncio.run(_drive())
    assert copied == f"W1-{P1}", copied
    assert ctrl_value == f"W1-{P1}", ctrl_value
    assert rc_copied == f"R1-{P1}", rc_copied
    assert rc_value == f"R1-{P1}", rc_value


def test_r_tui_044_1_10_command_palette_box_round_trip(tmp_path: Path) -> None:
    """R-TUI-044.1/10 (LinuxH): the command palette box round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            await pilot.press("ctrl+k")
            await pilot.pause()
            widget = app.query_one("#palette_input", Input)
            widget.focus()
            widget.value = f"W10-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return copied, widget.value

    copied, value = asyncio.run(_drive())
    assert copied == f"W10-{P1}", copied
    assert value == f"W10-{P1}", value


def test_r_tui_044_1_11_load_dialog_path_box_round_trip(tmp_path: Path) -> None:
    """R-TUI-044.1/11 (LinuxH): the Load dialog path box round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            widget.focus()
            widget.value = f"W11-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return copied, widget.value

    copied, value = asyncio.run(_drive())
    assert copied == f"W11-{P1}", copied
    assert value == f"W11-{P1}", value


def _multi_line_places():
    return [
        ("patch", "#patch_paste_text"),
        ("sje", "#sje_manual"),
    ]


@pytest.mark.parametrize(
    "place", _multi_line_places(), ids=[p[0] for p in _multi_line_places()]
)
def test_r_paste_18_walk_multi_line_round_trip(tmp_path: Path, place: tuple) -> None:
    """R-PASTE.18/1-2 (LinuxH): a Ctrl+C/Ctrl+V and a right-click round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")
    screen_key, widget_id = place

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            if screen_key == "sje":
                app.action_open_split_join_export()
            else:
                await _activate(app, pilot, screen_key)
            widget = app.query_one(widget_id, TextArea)
            widget.focus()
            await pilot.pause()
            widget.text = f"W1-{P2}"
            widget.select_all()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.text = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            ctrl_value = widget.text
            widget.text = f"R1-{P2}"
            widget.select_all()
            await pilot.pause()
            await right_click_app_route(app, widget)
            await pilot.pause()
            rc_copied = app.clipboard
            widget.text = ""
            await pilot.pause()
            await right_click_app_route(app, widget)
            await pilot.pause()
            return copied, ctrl_value, rc_copied, widget.text

    copied, ctrl_value, rc_copied, rc_value = asyncio.run(_drive())
    assert copied == f"W1-{P2}", copied
    assert ctrl_value == f"W1-{P2}", ctrl_value
    assert rc_copied == f"R1-{P2}", rc_copied
    assert rc_value == f"R1-{P2}", rc_value


def test_r_tui_044_1_7_flow_ref_box_round_trip(tmp_path: Path) -> None:
    """R-TUI-044.1/7 (LinuxH): the Flow Builder reference box round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")
    from tests.b97_fixtures import flow_project, open_flow_builder

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            await flow_project(app)
            await open_flow_builder(app, pilot)
            widget = app.query_one("#flow_ref", Input)
            widget.focus()
            widget.value = f"W7-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return copied, widget.value

    copied, value = asyncio.run(_drive())
    assert copied == f"W7-{P1}", copied
    assert value == f"W7-{P1}", value


def test_r_tui_044_1_8_fx_set_name_box_round_trip(tmp_path: Path) -> None:
    """R-TUI-044.1/8 (LinuxH): the Flow Execution set-name box round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")
    from tests.b97_fixtures import fx_project

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            await fx_project(app)
            app.action_show_screen("flow_execution")
            for _ in range(4):
                await pilot.pause()
            widget = app.query_one("#fx_set_name", Input)
            widget.focus()
            widget.value = f"W8-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return copied, widget.value

    copied, value = asyncio.run(_drive())
    assert copied == f"W8-{P1}", copied
    assert value == f"W8-{P1}", value


def test_r_tui_044_1_5_check_mem_address_box_round_trip(tmp_path: Path) -> None:
    """R-TUI-044.1/5 (LinuxH): the Check Editor memory-address box round trip."""
    if not _LINUXH:
        pytest.skip("Windows only")
    from tests.b97_fixtures import open_check_editor

    async def _drive() -> tuple:
        async for app, pilot in _app_with(tmp_path):
            await open_check_editor(app, pilot)
            widget = app.query_one("#check_mem_address_input", Input)
            widget.focus()
            widget.value = f"W5-{P1}"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            copied = app.clipboard
            widget.value = ""
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return copied, widget.value

    copied, value = asyncio.run(_drive())
    assert copied == f"W5-{P1}", copied
    assert value == f"W5-{P1}", value
