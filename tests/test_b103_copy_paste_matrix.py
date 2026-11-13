from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
from pathlib import Path

import pytest

from tests.support.b103_clipboard import (
    clipboard_isolated,
    other_program_read,
    other_program_write,
    require_isolated_clipboard,
    wait_for_copy_tail,
)

SEED = "SEED-1b"
A2L_THIRD_ROW = "ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING"
MAC_THIRD_ROW = "Curve_ExternalAxis"
SIZE = (118, 54)


def _is_winci() -> bool:
    return clipboard_isolated("windows")[0]


def _coverage_or_skip(route: str) -> str:
    if sys.platform == "win32":
        require_isolated_clipboard("windows")
        return "full"
    if sys.platform.startswith("linux"):
        if route == "P2":
            pytest.skip(
                "not_run: terminal paste requires the real copy->separate OS read "
                "artifact on isolated WinCI; Linux has no permitted OS read"
            )
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            pytest.skip(
                "not_run: Linux P1 requires a headless neutral host with "
                "DISPLAY and WAYLAND_DISPLAY unset"
            )
        return "partial"
    pytest.skip(
        "not_run: OS clipboard access is permitted only on isolated WinCI; "
        "the only non-WinCI arm is headless Linux P1"
    )


def _seed_os_clipboard() -> None:
    other_program_write(SEED)


def _read_os_clipboard() -> str:
    return other_program_read()


def _check_model_oracles(examples: Path) -> None:
    a2l = (examples / "ASAP2_Demo_V171.a2l").read_text(encoding="utf-8")
    names = set(
        re.findall(
            r"(?m)^\s*/begin\s+(?:MEASUREMENT|CHARACTERISTIC)\s+(\S+)",
            a2l,
        )
    )
    assert A2L_THIRD_ROW in names, "A2L canonical model does not contain the ledger row"
    mac_names = []
    for line in (examples / "synthetic_update_test1.mac").read_text(
        encoding="utf-8"
    ).splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            mac_names.append(stripped.split("=", 1)[0])
    assert len(mac_names) > 2
    assert mac_names[2] == MAC_THIRD_ROW, "MAC third canonical record changed"


async def _settle(pilot, rounds: int = 8) -> None:
    for _ in range(rounds):
        await pilot.pause(0.05)


async def _load_census(app, pilot, examples: Path) -> None:
    for name in ("prg.s19", "synthetic_update_test1.mac", "ASAP2_Demo_V171.a2l"):
        destination = Path(app.base_dir) / name
        shutil.copyfile(examples / name, destination)
        if name.endswith(".a2l"):
            app.load_a2l_from_path(destination)
        else:
            app.load_from_path(destination)
        ready = False
        for _ in range(200):
            await pilot.pause(0.05)
            if name.endswith(".s19") and app.current_file is not None:
                ready = True
            elif name.endswith(".a2l") and getattr(app, "current_a2l_data", None):
                ready = True
            elif name.endswith(".mac") and getattr(
                app.current_file, "mac_path", None
            ):
                ready = True
            if ready:
                break
        assert ready, f"census fixture did not load {name}"
        await _settle(pilot)


async def _drag(pilot, widget, start: tuple[int, int], end: tuple[int, int]) -> None:
    await pilot.mouse_down(widget, offset=start)
    await pilot.hover(widget, offset=end)
    await pilot.mouse_up(widget, offset=end)
    await _settle(pilot, 4)


def _rendered_text(widget) -> str:
    try:
        rendered = widget.render()
    except (AttributeError, TypeError):
        return ""
    return rendered.plain if hasattr(rendered, "plain") else str(rendered)


def _help_text_widget(screen):
    candidates = []
    for widget in screen.query("*"):
        text = _rendered_text(widget)
        if (
            getattr(widget, "allow_select", False)
            and widget.region.width > 1
            and widget.region.height > 1
            and len(text.splitlines()) >= 2
        ):
            candidates.append((len(text), widget))
    assert candidates, "Workspace help has no selectable multi-line text widget"
    return max(candidates, key=lambda item: item[0])[1]


async def _show_patch_json(app, pilot) -> None:
    await pilot.press("6")
    await _settle(pilot)
    await pilot.click("#patch_tab_json")
    await _settle(pilot)
    view = app.query_one("#patch_json_view")
    assert view.region.width > 0 and view.region.height > 0, (
        type(app.screen).__name__,
        view.region,
    )


async def _arm_source(app, pilot, source: int):
    if source == 1:
        await pilot.press("1")
        await _settle(pilot)
        widget = app.query_one("#hex_view")
        await _drag(pilot, widget, (2, 1), (40, 3))
        expected = app.screen.get_selected_text()
        assert expected and expected.count("\n") == 2
        assert len(set(expected.splitlines())) == 3
        return expected, widget, (10, 2)
    if source == 2:
        await pilot.press("1")
        await _settle(pilot)
        widget = app.query_one("#ws_stats")
        await _drag(
            pilot,
            widget,
            (0, 0),
            (max(1, widget.region.width - 1), 4),
        )
        expected = app.screen.get_selected_text()
        assert expected and len(expected.splitlines()) == 5
        return expected, widget, (2, 2)
    if source == 3:
        await pilot.press("1")
        await _settle(pilot)
        widget = app.query_one("#a2l_view")
        full_text = _rendered_text(widget)
        await _drag(
            pilot,
            widget,
            (0, 0),
            (max(1, widget.region.width - 1), 1),
        )
        expected = app.screen.get_selected_text()
        assert expected and len(expected.splitlines()) == 2
        assert expected != full_text, "AT-I1b-3 must copy a selection, not a whole view"
        return expected, widget, (2, 1)
    if source == 4:
        await pilot.press("2")
        await _settle(pilot)
        widget = app.query_one("#a2l_tags_list")
        assert widget.row_count > 2
        widget.move_cursor(row=0)
        await _settle(pilot, 2)
        return A2L_THIRD_ROW, widget, (4, widget.header_height + 2)
    if source == 5:
        await pilot.press("3")
        await _settle(pilot)
        widget = app.query_one("#mac_records_list")
        assert widget.row_count > 2
        widget.move_cursor(row=0)
        await _settle(pilot, 2)
        return MAC_THIRD_ROW, widget, (4, widget.header_height + 2)
    if source == 6:
        await _show_patch_json(app, pilot)
        widget = app.query_one("#patch_json_view")
        await pilot.click(widget, offset=(0, 1))
        assert app.focused is widget
        await pilot.press("shift+down", "shift+down")
        await _settle(pilot, 4)
        expected = widget.selected_text
        assert expected and len(expected.splitlines()) == 2
        return expected, widget, (1, 1)
    if source == 7:
        await pilot.press("1")
        await _settle(pilot)
        await pilot.press("?")
        await _settle(pilot)
        widget = _help_text_widget(app.screen)
        expected = None
        for end_y in range(1, widget.region.height):
            app.screen.clear_selection()
            await _drag(
                pilot,
                widget,
                (0, 0),
                (max(1, widget.region.width - 1), end_y),
            )
            candidate = app.screen.get_selected_text()
            if candidate and sum(
                bool(line.strip()) for line in candidate.splitlines()
            ) == 2:
                expected = candidate
                break
        assert expected, (widget.region, app.screen.get_selected_text())
        assert expected != _rendered_text(widget)
        return expected, widget, (2, 1)
    raise AssertionError(f"unknown source {source}")


async def _right_click(app, pilot, widget, offset: tuple[int, int]) -> None:
    from textual import events

    region = widget.region
    x = region.x + offset[0]
    y = region.y + offset[1]
    for event_type in (events.MouseDown, events.MouseUp):
        app.post_message(
            event_type(
                None,
                x,
                y,
                0,
                0,
                3,
                False,
                False,
                False,
                screen_x=x,
                screen_y=y,
            )
        )
    await pilot.pause()


def _copy_notice(expected: str) -> str:
    lines = expected.count("\n") + (0 if expected.endswith("\n") else 1)
    suffix = "line" if lines == 1 else "lines"
    return f"Copied {lines} {suffix} to the clipboard."


def _assert_copy_notice(app, before: list, expected: str) -> None:
    previous = {id(notification) for notification in before}
    current = [
        notification
        for notification in list(app._notifications)
        if id(notification) not in previous
    ]
    copies = [
        notification
        for notification in current
        if str(notification.message).startswith("Copied")
    ]
    expected_notice = _copy_notice(expected)
    assert len(copies) == 1, (expected_notice, [str(n.message) for n in current])
    assert str(copies[0].message) == expected_notice
    assert copies[0].severity == "information"


async def _prepare_target(app, pilot, target: str):
    if target == "T1":
        await pilot.press("2")
        await _settle(pilot)
        await pilot.press("/")
        await _settle(pilot)
        widget = app.query_one("#a2l_tags_filter_input")
        widget.focus()
        await _settle(pilot, 2)
        assert widget.value == ""
        assert app.focused is widget
        return widget
    await _show_patch_json(app, pilot)
    widget = app.query_one("#patch_paste_text")
    await pilot.click(widget, offset=(2, 1))
    await pilot.press("f7")
    await _settle(pilot, 4)
    assert app.focused is widget
    assert widget.selected_text
    return widget


async def _run_cell(
    tmp_path: Path,
    source: int,
    target: str,
    route: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from s19_app.tui import app as app_module
    from s19_app.tui import os_clipboard_input as clipboard_module
    from s19_app.tui.app import S19TuiApp
    from textual import events
    from textual.app import App

    root = Path(__file__).resolve().parents[1]
    examples = root / "examples" / "case_00_public"
    _check_model_oracles(examples)
    if _is_winci():
        _seed_os_clipboard()
    original_tail = clipboard_module._mirror_and_write_os_clipboard
    tail_marker = {"started": False, "ended": False}
    tail_payloads = []

    async def marked_tail(app, text):
        tail_payloads.append(text)
        tail_marker["started"] = True
        try:
            return await original_tail(app, text)
        finally:
            tail_marker["ended"] = True

    monkeypatch.setattr(
        clipboard_module, "_mirror_and_write_os_clipboard", marked_tail
    )
    monkeypatch.setattr(app_module.deps, "_mirror_and_write_os_clipboard", marked_tail)
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=SIZE) as pilot:
        await _settle(pilot)
        await _load_census(app, pilot, examples)
        App.copy_to_clipboard(app, SEED)
        expected, source_widget, offset = await _arm_source(app, pilot, source)
        before = list(app._notifications)
        await _right_click(app, pilot, source_widget, offset)
        await wait_for_copy_tail(pilot, tail_marker)
        assert tail_payloads == [expected]
        if source == 7:
            await pilot.press("escape")
            await _settle(pilot)
        if _is_winci():
            _assert_copy_notice(app, before, expected)
        assert app.clipboard == expected, (
            f"AT-I1b-{source}: right-click copy must replace the app seed with "
            "the independently captured source before paste"
        )
        os_artifact = _read_os_clipboard() if _is_winci() else None
        if os_artifact is not None:
            assert os_artifact == expected, (
                f"AT-I1b-{source}: separate Get-Clipboard read must equal the "
                "independent source, not the seed or a projected value"
            )
        target_widget = await _prepare_target(app, pilot, target)
        if route == "P1":
            await pilot.press("ctrl+v")
        else:
            assert os_artifact is not None
            app.post_message(events.Paste(os_artifact))
        await _settle(pilot)
        if target == "T1":
            actual = target_widget.value
            wanted = expected.split("\n", 1)[0]
        else:
            actual = target_widget.text
            wanted = expected
        assert actual == wanted, (
            f"AT-I1b-{source} {target}/{route}: expected exactly {wanted!r} once"
        )


AT_CELLS = [
    pytest.param(1, "T1", "P1", id="AT-I1b-1/1-T1-P1"),
    pytest.param(1, "T1", "P2", id="AT-I1b-1/2-T1-P2"),
    pytest.param(1, "T2", "P1", id="AT-I1b-1/3-T2-P1"),
    pytest.param(1, "T2", "P2", id="AT-I1b-1/4-T2-P2"),
    pytest.param(2, "T1", "P1", id="AT-I1b-2/1-T1-P1"),
    pytest.param(2, "T1", "P2", id="AT-I1b-2/2-T1-P2"),
    pytest.param(2, "T2", "P1", id="AT-I1b-2/3-T2-P1"),
    pytest.param(2, "T2", "P2", id="AT-I1b-2/4-T2-P2"),
    pytest.param(3, "T1", "P1", id="AT-I1b-3/1-T1-P1"),
    pytest.param(3, "T1", "P2", id="AT-I1b-3/2-T1-P2"),
    pytest.param(3, "T2", "P1", id="AT-I1b-3/3-T2-P1"),
    pytest.param(3, "T2", "P2", id="AT-I1b-3/4-T2-P2"),
    pytest.param(4, "T1", "P1", id="AT-I1b-4/1-T1-P1"),
    pytest.param(4, "T1", "P2", id="AT-I1b-4/2-T1-P2"),
    pytest.param(4, "T2", "P1", id="AT-I1b-4/3-T2-P1"),
    pytest.param(4, "T2", "P2", id="AT-I1b-4/4-T2-P2"),
    pytest.param(5, "T1", "P1", id="AT-I1b-5/1-T1-P1"),
    pytest.param(5, "T1", "P2", id="AT-I1b-5/2-T1-P2"),
    pytest.param(5, "T2", "P1", id="AT-I1b-5/3-T2-P1"),
    pytest.param(5, "T2", "P2", id="AT-I1b-5/4-T2-P2"),
    pytest.param(6, "T1", "P1", id="AT-I1b-6/1-T1-P1"),
    pytest.param(6, "T1", "P2", id="AT-I1b-6/2-T1-P2"),
    pytest.param(6, "T2", "P1", id="AT-I1b-6/3-T2-P1"),
    pytest.param(6, "T2", "P2", id="AT-I1b-6/4-T2-P2"),
    pytest.param(7, "T1", "P1", id="AT-I1b-7/1-T1-P1"),
    pytest.param(7, "T1", "P2", id="AT-I1b-7/2-T1-P2"),
    pytest.param(7, "T2", "P1", id="AT-I1b-7/3-T2-P1"),
    pytest.param(7, "T2", "P2", id="AT-I1b-7/4-T2-P2"),
]
assert len(AT_CELLS) == 28
assert len({cell.id for cell in AT_CELLS}) == 28


@pytest.mark.parametrize(("source", "target", "route"), AT_CELLS)
def test_copy_paste_acceptance_cell(
    tmp_path: Path,
    source: int,
    target: str,
    route: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _coverage_or_skip(route)
    asyncio.run(_run_cell(tmp_path, source, target, route, monkeypatch))


@pytest.mark.skip(
    reason=(
        "AT-I1b-8 manual not_run: only the operator may run the six Windows "
        "Terminal steps and choose to use his own clipboard; no agent access"
    )
)
def test_manual_windows_terminal_operator_acceptance() -> None:
    raise AssertionError("AT-I1b-8 is manual and must never execute in automation")
