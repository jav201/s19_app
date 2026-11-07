"""Batch-103 Inc 1a clipboard core — LinuxH and static cases (G-T1).

Summary:
    The platform-neutral and Linux-only half of the Inc 1a clipboard cases:
    the paste/copy/cut rules, the terminal route, the paste limit, the unsafe
    paste-character strip, the Load dialog's path-box refusal, the OSC 52
    copy, the right-click (LinuxH arms), the LinuxH timing arms, the text-box
    censuses, the workflow guard (R-PASTE.20/1), the isolation guard cases
    (R-PASTE.21/1-4), the probe skip/fail cases (R-PASTE.22/1, R-PASTE.23/1-2)
    and the redaction-gate root case (R-PASTE.36/1).

    Every LinuxH arm asserts ``DISPLAY`` / ``WAYLAND_DISPLAY`` are unset (no
    OS clipboard reachable) and drives the product unstubbed except where a
    case names a seam. The two LinuxX arms (R-TUI-043.6/4, R-PASTE.9/3) run
    under a private Xvfb display with ``xclip`` and are skipped when neither
    is available. Timing arms are ``@pytest.mark.serial_timing`` and route
    every bound through :func:`tests.support.timing.timing_bound` and
    ``report_margin``.

Dependencies:
    Uses:
        - ``tests.support.b103_clipboard`` (payloads, helpers)
        - ``tests.support.timing`` (timing_bound, report_margin)
        - ``s19_app.tui.os_clipboard_input`` / ``capped_text_area``
    Used by:
        - the Inc 1a E4 test run (RED on base, GREEN on the tree)
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from textual import events
from textual.widgets import Button, Input, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.capped_text_area import CappedTextArea
from s19_app.tui.os_clipboard_input import OsClipboardInput
from tests.support.b103_clipboard import (
    CAP,
    P1000,
    P70K,
    P2,
    P2_ESC,
    P_CTRL,
    P_CTRL_L,
    P_CTRL_M,
    P1,
    READ_FAIL_WARNING,
    WRITE_FAIL_WARNING,
    _box,
    _box_lines,
    _set_box,
    install_log_capture,
    install_notice_capture,
    install_osc52_spy,
    remove_log_capture,
    right_click_app_route,
    show_patch_paste,
    terminal_paste,
    typed_key_time,
)
from tests.support.timing import report_margin, timing_bound

_LINUXH = sys.platform != "win32"

# ---------------------------------------------------------------------------
# Driving helpers
# ---------------------------------------------------------------------------


async def _drive_real_app(tmp_path: Path, screen_key: str | None = None):
    """Start the real app, optionally activate a rail screen, and return
    ``(app, pilot)`` after a settle pause."""
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        if screen_key is not None:
            app.action_show_screen(screen_key)
            for _ in range(4):
                await pilot.pause()
        yield app, pilot


async def _box_a(tmp_path: Path, screen_key: str = "a2l"):
    """Yield ``(app, pilot, widget)`` for Box A (``#a2l_tags_filter_input``)."""
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen(screen_key)
        for _ in range(4):
            await pilot.pause()
        widget = app.query_one("#a2l_tags_filter_input", Input)
        widget.focus()
        await pilot.pause()
        yield app, pilot, widget


async def _box_m(tmp_path: Path):
    """Yield ``(app, pilot, widget)`` for Box M (``#patch_paste_text``)."""
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen("patch")
        for _ in range(4):
            await pilot.pause()
        widget = app.query_one("#patch_paste_text", TextArea)
        widget.text = ""
        widget.focus()
        await pilot.pause()
        yield app, pilot, widget


def _run_a(tmp_path: Path, body):
    """Run ``body(app, pilot, widget)`` inside the real app on the A2L screen."""
    async def _main():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            widget = app.query_one("#a2l_tags_filter_input", Input)
            widget.focus()
            return await body(app, pilot, widget)
    return asyncio.run(_main())


def _run_m(tmp_path: Path, body):
    """Run ``body(app, pilot, widget)`` inside the real app on the Patch screen."""
    async def _main():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            await show_patch_paste(app, pilot)
            widget = app.query_one("#patch_paste_text", TextArea)
            widget.text = ""
            widget.focus()
            return await body(app, pilot, widget)
    return asyncio.run(_main())


def _run_one(box_kind: str, body):
    """Run ``body(app, pilot, widget)`` inside the one-box app (Box 1 / Box 2)."""
    async def _main():
        from tests.support.b103_clipboard import _OneBoxApp

        app = _OneBoxApp(box_kind)
        async with app.run_test(size=(80, 30)) as pilot:
            await pilot.pause()
            widget = app.query_one("#box")
            widget.focus()
            return await body(app, pilot, widget)
    return asyncio.run(_main())


def _assert_linuxh_headless() -> None:
    assert not os.environ.get("DISPLAY"), "LinuxH requires DISPLAY unset"
    assert not os.environ.get("WAYLAND_DISPLAY"), "LinuxH requires WAYLAND_DISPLAY unset"


# ---------------------------------------------------------------------------
# R-TUI-043.6 — no OS text → the app clipboard
# ---------------------------------------------------------------------------


def test_r_tui_043_6_1_linux_ctrl_v_pastes_app_clipboard(tmp_path: Path) -> None:
    """R-TUI-043.6/1 (LinuxH): Ctrl+V pastes the app clipboard, both classes."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box_a = app.query_one("#a2l_tags_filter_input", Input)
            box_a.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            await pilot.pause()
            a_value = box_a.value
            await show_patch_paste(app, pilot)
            box_m = app.query_one("#patch_paste_text", TextArea)
            box_m.text = ""
            box_m.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            await pilot.pause()
            return a_value, box_m.text

    a_value, m_value = asyncio.run(_drive())
    assert a_value == "APP-TEXT", a_value
    assert m_value == "APP-TEXT", m_value


# ---------------------------------------------------------------------------
# R-TUI-043.7 / .8 — neither clipboard holds text
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_7_1_and_043_8_1_neither_clipboard_warns_and_selects(
    tmp_path: Path, kind: str
) -> None:
    """R-TUI-043.7/1 + R-TUI-043.8/1 (LinuxH): warning + whole text selected."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = ""
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            if kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
            _set_box(widget, "KEEP")
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            await pilot.pause()
            selected = widget.selected_text
            value = _box(widget)
            return notices, selected, value

    notices, selected, value = asyncio.run(_drive())
    assert notices, "a warning notice must be painted"
    severity, message = notices[-1]
    assert severity == "warning", notices
    assert message == READ_FAIL_WARNING, notices
    assert selected == "KEEP", f"whole text must be selected; got {selected!r}"
    assert value == "KEEP", value


# ---------------------------------------------------------------------------
# R-TUI-043.12 / .13 — log behaviour
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_12_1_warning_line_when_no_text_read_on_linux(
    tmp_path: Path, kind: str
) -> None:
    """R-TUI-043.12/1 (LinuxH): ≥ 1 WARNING of os_clipboard_input per paste."""
    _assert_linuxh_headless()

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
            if kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            await pilot.pause()
            warnings = [
                r for r in records
                if r[0] == "s19_app.tui.os_clipboard_input" and r[1] == "WARNING"
            ]
            remove_log_capture(records)
            return len(warnings)

    assert asyncio.run(_drive()) >= 1


def test_r_tui_043_13_1_no_clipboard_text_reaches_the_log(tmp_path: Path) -> None:
    """R-TUI-043.13/1 (LinuxH arm): a paste and a copy leak nothing to the log."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
            app._clipboard = "SECRET-TEXT-42"
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            box.value = "SECRET-COPY-43"
            box.selection = (0, len(box.value))
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            remove_log_capture(records)
            return [m for _, _, m in records]

    messages = asyncio.run(_drive())
    assert not any("SECRET-TEXT-42" in m for m in messages), messages
    assert not any("SECRET-COPY-43" in m for m in messages), messages


# ---------------------------------------------------------------------------
# R-PASTE.1 / R-TUI-044.4 — the terminal route
# ---------------------------------------------------------------------------


def test_r_paste_1_1_terminal_paste_single_line_takes_first_line(tmp_path: Path) -> None:
    """R-PASTE.1/1 (LinuxH): ``L1\\nL2`` → ``L1``."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            await terminal_paste(app, "L1\nL2")
            await pilot.pause()
            return widget.value

    assert asyncio.run(_drive()) == "L1"


def test_r_paste_1_2_terminal_paste_first_line_non_codepage(tmp_path: Path) -> None:
    """R-PASTE.1/2 (LinuxH): the first line with emoji/CJK lands unchanged."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            await terminal_paste(app, "Ñoño Ж 漢字 😀\nsecond")
            await pilot.pause()
            return widget.value

    assert asyncio.run(_drive()) == "Ñoño Ж 漢字 😀"


def test_r_tui_044_4_1_terminal_paste_multi_line_inserts_every_line_once(
    tmp_path: Path,
) -> None:
    """R-TUI-044.4/1 (LinuxH): ``L1\\nL2`` → ``L1\\nL2`` once."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        async for app, pilot, widget in _box_m(tmp_path):
            await terminal_paste(app, "L1\nL2")
            await pilot.pause()
            return widget.text

    assert asyncio.run(_drive()) == "L1\nL2"


# ---------------------------------------------------------------------------
# R-TUI-044.2 — the paste limit
# ---------------------------------------------------------------------------


def test_r_tui_044_2_1_terminal_paste_single_line_capped(tmp_path: Path) -> None:
    """R-TUI-044.2/1 (LinuxH): a 70,000-char terminal paste → 65,536."""
    _assert_linuxh_headless()

    async def _drive() -> int:
        async for app, pilot, widget in _box_a(tmp_path):
            await terminal_paste(app, P70K)
            await pilot.pause()
            return len(widget.value)

    assert asyncio.run(_drive()) == CAP


def test_r_tui_044_2_2_app_clipboard_fallback_single_line_capped(tmp_path: Path) -> None:
    """R-TUI-044.2/2 (LinuxH): a 70,000-char app clipboard → 65,536."""
    _assert_linuxh_headless()

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = P70K
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            widget = app.query_one("#a2l_tags_filter_input", Input)
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            await pilot.pause()
            return len(widget.value)

    assert asyncio.run(_drive()) == CAP


def test_r_tui_044_2_3_terminal_paste_multi_line_capped(tmp_path: Path) -> None:
    """R-TUI-044.2/3 (LinuxH): a 70,000-char terminal paste into Box M → 65,536."""
    _assert_linuxh_headless()

    async def _drive() -> int:
        async for app, pilot, widget in _box_m(tmp_path):
            await terminal_paste(app, P70K)
            await pilot.pause()
            return len(widget.text)

    assert asyncio.run(_drive()) == CAP


def test_r_tui_044_2_5_load_path_box_keeps_its_own_limit(tmp_path: Path) -> None:
    """R-TUI-044.2/5 (LinuxH): 5,000 chars refused whole by ``#load_path``."""
    _assert_linuxh_headless()
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            widget.focus()
            await pilot.pause()
            await terminal_paste(app, "a" * 5000)
            await pilot.pause()
            return widget.value

    assert asyncio.run(_drive()) == ""


# ---------------------------------------------------------------------------
# R-PASTE.34 / .35 / R-LOADDLG.20 — unsafe paste characters (E3)
# ---------------------------------------------------------------------------


def test_r_paste_34_1_terminal_paste_single_line_strips_unsafe(tmp_path: Path) -> None:
    """R-PASTE.34/1 (LinuxH): P-CTRL → ``A[13DB\\x00C``; P-CTRL-L → ``L1[2J``."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        async for app, pilot, widget in _box_a(tmp_path):
            await terminal_paste(app, P_CTRL)
            await pilot.pause()
            first = widget.value
            widget.value = ""
            await pilot.pause()
            await terminal_paste(app, P_CTRL_L)
            await pilot.pause()
            return first, widget.value

    first, second = asyncio.run(_drive())
    assert first == "A[13DB\x00C", repr(first)
    assert second == "L1[2J", repr(second)


def test_r_paste_34_3_app_clipboard_fallback_single_line_strips(tmp_path: Path) -> None:
    """R-PASTE.34/3 (LinuxH): the app-clipboard fallback strips as /1."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            widget = app.query_one("#a2l_tags_filter_input", Input)
            widget.focus()
            app._clipboard = P_CTRL
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            first = widget.value
            widget.value = ""
            app._clipboard = P_CTRL_L
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return first, widget.value

    first, second = asyncio.run(_drive())
    assert first == "A[13DB\x00C", repr(first)
    assert second == "L1[2J", repr(second)


def test_r_paste_34_4_right_click_paste_single_line_strips(tmp_path: Path) -> None:
    """R-PASTE.34/4 (LinuxH): a right-click paste strips as /1."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            widget = app.query_one("#a2l_tags_filter_input", Input)
            widget.focus()
            app._clipboard = P_CTRL
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            first = widget.value
            widget.value = ""
            app._clipboard = P_CTRL_L
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return first, widget.value

    first, second = asyncio.run(_drive())
    assert first == "A[13DB\x00C", repr(first)
    assert second == "L1[2J", repr(second)


def test_r_paste_34_5_load_path_not_stripped_refuses_control_whole(
    tmp_path: Path,
) -> None:
    """R-PASTE.34/5 (LinuxH): ``#load_path`` refuses NUL / ESC payloads whole."""
    _assert_linuxh_headless()
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            values = []
            # terminal pastes
            for payload in ("a\x00.s19", "a\x1b[2K.s19"):
                widget.value = ""
                widget.focus()
                await pilot.pause()
                await terminal_paste(app, payload)
                await pilot.pause()
                values.append(widget.value)
            # app-clipboard Ctrl+V
            for payload in ("a\x00.s19", "a\x1b[2K.s19"):
                widget.value = ""
                app._clipboard = payload
                await pilot.pause()
                await pilot.press("ctrl+v")
                await pilot.pause()
                values.append(widget.value)
            return values

    values = asyncio.run(_drive())
    assert values == ["", "", "", ""], values


def test_r_paste_35_1_terminal_paste_multi_line_strips(tmp_path: Path) -> None:
    """R-PASTE.35/1 (LinuxH): P-CTRL-M → ``["A[13DB\\x00C\\tD", "E"]``."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        async for app, pilot, widget in _box_m(tmp_path):
            await terminal_paste(app, P_CTRL_M)
            await pilot.pause()
            return _box_lines(widget)

    assert asyncio.run(_drive()) == ["A[13DB\x00C\tD", "E"]


def test_r_paste_35_3_app_clipboard_fallback_multi_line_strips(tmp_path: Path) -> None:
    """R-PASTE.35/3 (LinuxH): the app-clipboard fallback strips as /1."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            await show_patch_paste(app, pilot)
            widget = app.query_one("#patch_paste_text", TextArea)
            widget.text = ""
            widget.focus()
            app._clipboard = P_CTRL_M
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return _box_lines(widget)

    assert asyncio.run(_drive()) == ["A[13DB\x00C\tD", "E"]


def test_r_paste_35_4_right_click_paste_multi_line_strips(tmp_path: Path) -> None:
    """R-PASTE.35/4 (LinuxH): a right-click paste strips as /1."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            await show_patch_paste(app, pilot)
            widget = app.query_one("#patch_paste_text", TextArea)
            widget.text = ""
            widget.focus()
            app._clipboard = P_CTRL_M
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return _box_lines(widget)

    assert asyncio.run(_drive()) == ["A[13DB\x00C\tD", "E"]


def test_r_loaddlg_20_1_terminal_paste_path_box_refuses_unsafe(tmp_path: Path) -> None:
    """R-LOADDLG.20/1 (LinuxH): C1 / lone surrogate / bidi refused whole, clean lands."""
    _assert_linuxh_headless()
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            values = []
            for payload in ("a\x9b31m.s19", "a\ud800.s19", "a\u202e.s19", "a.s19"):
                widget.value = ""
                widget.focus()
                await pilot.pause()
                await terminal_paste(app, payload)
                await pilot.pause()
                values.append(widget.value)
            return values

    values = asyncio.run(_drive())
    assert values == ["", "", "", "a.s19"], values


def test_r_loaddlg_20_2_ctrl_v_path_box_refuses_unsafe(tmp_path: Path) -> None:
    """R-LOADDLG.20/2 (LinuxH): the app-clipboard Ctrl+V route refuses as /1."""
    _assert_linuxh_headless()
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            values = []
            for payload in ("a\x9b31m.s19", "a\ud800.s19", "a\u202e.s19", "a.s19"):
                widget.value = ""
                widget.focus()
                app._clipboard = payload
                await pilot.pause()
                await pilot.press("ctrl+v")
                await pilot.pause()
                values.append(widget.value)
            return values

    values = asyncio.run(_drive())
    assert values == ["", "", "", "a.s19"], values


def test_r_loaddlg_20_3_right_click_path_box_refuses_unsafe(tmp_path: Path) -> None:
    """R-LOADDLG.20/3 (LinuxH): a right-click paste with no selection refuses as /1."""
    _assert_linuxh_headless()
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            values = []
            for payload in ("a\x9b31m.s19", "a\ud800.s19", "a\u202e.s19", "a.s19"):
                widget.value = ""
                widget.focus()
                app._clipboard = payload
                await pilot.pause()
                await right_click_app_route(app, pilot, widget)
                await pilot.pause()
                values.append(widget.value)
            return values

    values = asyncio.run(_drive())
    assert values == ["", "", "", "a.s19"], values


def test_r_loaddlg_20_4_path_box_refuses_del_payload(tmp_path: Path) -> None:
    """R-LOADDLG.20/4 (LinuxH): a DEL payload is refused; a typed clean path lands."""
    _assert_linuxh_headless()
    from tests.support.b100_load_dialog import bare_path_dialog

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(bare_path_dialog())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            widget.focus()
            await pilot.pause()
            await terminal_paste(app, "b\x7f.s19")
            await pilot.pause()
            first = widget.value
            widget.value = ""
            app._clipboard = "b\x7f.s19"
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            second = widget.value
            widget.value = ""
            await pilot.pause()
            await pilot.press("a")
            await pilot.pause()
            return first, second, widget.value

    first, second, typed = asyncio.run(_drive())
    assert first == "" and second == "", (first, second)
    assert typed == "a", typed


# ---------------------------------------------------------------------------
# Copy and cut (LinuxH arms)
# ---------------------------------------------------------------------------


def test_r_paste_3_copy_puts_selection_on_app_clipboard(tmp_path: Path) -> None:
    """R-PASTE.3/1-2 (LinuxH): Ctrl+C puts the selection on the app clipboard."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "COPYME-1"
            box.selection = (0, len(box.value))
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            single = app.clipboard
            await show_patch_paste(app, pilot)
            ta = app.query_one("#patch_paste_text", TextArea)
            ta.text = "COPYME-2"
            ta.select_all()
            ta.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            return single, app.clipboard

    single, multi = asyncio.run(_drive())
    assert single == "COPYME-1", single
    assert multi == "COPYME-2", multi


def test_r_paste_4_copy_leaves_box_unchanged(tmp_path: Path) -> None:
    """R-PASTE.4/1-2 (LinuxH): Ctrl+C leaves the box text unchanged."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "COPYME-1"
            box.selection = (0, len(box.value))
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            return box.value

    assert asyncio.run(_drive()) == "COPYME-1"


@pytest.mark.parametrize("action", ["ctrl+c", "ctrl+x", "ctrl+x_multi"], ids=["c", "x", "x_multi"])
def test_r_paste_5_no_selection_changes_no_clipboard(tmp_path: Path, action: str) -> None:
    """R-PASTE.5/1-3 (LinuxH): no selection → the app clipboard keeps BEFORE."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "BEFORE"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if action == "x_multi":
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
                widget.text = "KEEP"
                widget.selection = ((0, 4), (0, 4))
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+x")
            else:
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
                widget.focus()
                await pilot.pause()
                widget.value = "KEEP"
                widget.selection = (4, 4)
                await pilot.pause()
                await pilot.press(action)
            await pilot.pause()
            await pilot.pause()
            return app.clipboard

    assert asyncio.run(_drive()) == "BEFORE"


def test_r_paste_6_cut_copies_selection(tmp_path: Path) -> None:
    """R-PASTE.6/1 (LinuxH): Ctrl+X copies the selection to the app clipboard."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "CUTME-1"
            box.selection = (0, len(box.value))
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+x")
            await pilot.pause()
            await pilot.pause()
            return app.clipboard

    assert asyncio.run(_drive()) == "CUTME-1"


def test_r_paste_7_cut_removes_selection(tmp_path: Path) -> None:
    """R-PASTE.7/1-2 (LinuxH): ``DE AD BE EF`` with ``DE AD`` selected → `` BE EF``."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            box.value = "DE AD BE EF"
            box.selection = (0, 5)
            await pilot.pause()
            await pilot.press("ctrl+x")
            await pilot.pause()
            return box.value, app.clipboard

    value, clip = asyncio.run(_drive())
    assert value == " BE EF", value
    assert clip == "DE AD", clip


def test_r_paste_8_no_selection_cut_cuts_cursor_line(tmp_path: Path) -> None:
    """R-PASTE.8/1 (LinuxH): a no-selection cut removes the cursor line."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            await show_patch_paste(app, pilot)
            ta = app.query_one("#patch_paste_text", TextArea)
            ta.text = "first\nline_to_cut\nthird"
            ta.selection = ((1, 2), (1, 2))
            ta.focus()
            await pilot.pause()
            await pilot.press("ctrl+x")
            await pilot.pause()
            return ta.text, app.clipboard

    text, clip = asyncio.run(_drive())
    assert text == "first\nthird", text
    assert clip.rstrip("\r\n") == "line_to_cut", clip


@pytest.mark.parametrize("kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_9_1_write_failure_warning_on_linux(tmp_path: Path, kind: str) -> None:
    """R-PASTE.9/1 (LinuxH): the write failure warning after every copy and cut."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            for _ in range(2):
                if kind == "a":
                    app.action_show_screen("a2l")
                    for _ in range(4):
                        await pilot.pause()
                    widget = app.query_one("#a2l_tags_filter_input", Input)
                else:
                    app.action_show_screen("patch")
                    for _ in range(4):
                        await pilot.pause()
                    widget = app.query_one("#patch_paste_text", TextArea)
                _set_box(widget, "KEEP")
                widget.selection = (0, 4) if kind == "a" else ((0, 0), (0, 4))
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+c")
                await pilot.pause()
                await pilot.press("ctrl+x")
                await pilot.pause()
                await pilot.pause()
            return notices

    notices = asyncio.run(_drive())
    warnings = [n for n in notices if n[0] == "warning"]
    assert len(warnings) == 4, notices
    assert all(m == WRITE_FAIL_WARNING for _, m in warnings), notices


def test_r_paste_10_1_warning_line_per_failed_copy_without_text(tmp_path: Path) -> None:
    """R-PASTE.10/1 (LinuxH): ≥ 1 WARNING per failed copy; no copied text."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "SECRET-COPY-43"
            box.selection = (0, len(box.value))
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            remove_log_capture(records)
            return [(r[1], r[2]) for r in records]

    records = asyncio.run(_drive())
    warnings = [m for level, m in records if level == "WARNING"]
    assert warnings, records
    assert not any("SECRET-COPY-43" in m for m in [m for _, m in records]), records


def test_r_paste_12_1_copy_over_limit_keeps_first_65536(tmp_path: Path) -> None:
    """R-PASTE.12/1 (LinuxH): a 70,000-char copy → 65,536 in app + OSC 52."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            osc = install_osc52_spy(app)
            await show_patch_paste(app, pilot)
            ta = app.query_one("#patch_paste_text", TextArea)
            ta.text = P70K
            ta.select_all()
            ta.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            return len(app.clipboard), [len(r) for r in osc]

    clip_len, osc_lens = asyncio.run(_drive())
    assert clip_len == CAP, clip_len
    assert osc_lens == [CAP], osc_lens


@pytest.mark.parametrize(
    "action,box_kind",
    [("copy", "a"), ("cut", "a"), ("copy", "m"), ("cut", "m"), ("line_cut", "m")],
    ids=["copy_a", "cut_a", "copy_m", "cut_m", "line_cut_m"],
)
def test_r_paste_15_one_osc52_request_per_copy(tmp_path: Path, action: str, box_kind: str) -> None:
    """R-PASTE.15/1-5 (LinuxH): exactly one OSC 52 request, decoding to the text."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            osc = install_osc52_spy(app)
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
                widget.value = P1
                widget.selection = (0, len(P1))
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+c" if action == "copy" else "ctrl+x")
                await pilot.pause()
                return len(osc), osc[0] if osc else None
            await show_patch_paste(app, pilot)
            ta = app.query_one("#patch_paste_text", TextArea)
            if action == "line_cut":
                ta.text = "first\nline_to_cut\nthird"
                ta.selection = ((1, 2), (1, 2))
                ta.focus()
                await pilot.pause()
                await pilot.press("ctrl+x")
                await pilot.pause()
                return len(osc), osc[0] if osc else None
            ta.text = P2
            ta.select_all()
            ta.focus()
            await pilot.pause()
            await pilot.press("ctrl+c" if action == "copy" else "ctrl+x")
            await pilot.pause()
            return len(osc), osc[0] if osc else None

    count, payload = asyncio.run(_drive())
    assert count == 1, (count, payload)
    if action == "line_cut":
        assert payload.rstrip("\r\n") == "line_to_cut", payload
    elif box_kind == "a":
        assert payload == P1, payload
    else:
        assert payload == P2, payload


# ---------------------------------------------------------------------------
# Right-click (LinuxH arms)
# ---------------------------------------------------------------------------


async def _one_box_app(box_kind: str):
    from tests.support.b103_clipboard import _OneBoxApp

    app = _OneBoxApp(box_kind)
    async with app.run_test(size=(80, 30)) as pilot:
        await pilot.pause()
        widget = app.query_one("#box", (OsClipboardInput if box_kind == "input" else CappedTextArea))
        widget.focus()
        await pilot.pause()
        yield app, pilot, widget

@pytest.mark.parametrize("box_kind", ["input", "textarea"], ids=["single", "multi"])
def test_r_paste_25_right_click_puts_selection_on_app_clipboard(
    tmp_path: Path, box_kind: str
) -> None:
    """R-PASTE.25/1-2 (LinuxH): a right-click on a shown selection copies it."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app._clipboard = "BEFORE"
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            box.value = "AAAA-BBBB"
            box.selection = (0, 4)
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            return app.clipboard

    assert asyncio.run(_drive()) == "AAAA"


@pytest.mark.parametrize("box_kind", ["input", "textarea"], ids=["single", "multi"])
def test_r_paste_26_right_click_copy_leaves_text_and_selection(
    tmp_path: Path, box_kind: str
) -> None:
    """R-PASTE.26/1-2 (LinuxH): the box's text and selection are unchanged."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app._clipboard = "BEFORE"
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            box.value = "AAAA-BBBB"
            box.selection = (0, 4)
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            return box.value, box.selection

    value, selection = asyncio.run(_drive())
    assert value == "AAAA-BBBB", value
    assert tuple(selection) == (0, 4), selection


def test_r_paste_29_1_right_click_no_selection_pastes_at_cursor(tmp_path: Path) -> None:
    """R-PASTE.29/1 (LinuxH): a right-click pastes the first line at the cursor."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        async for app, pilot, widget in _one_box_app("input"):
            widget.value = "ab"
            widget.selection = (1, 1)  # cursor between a and b
            widget.focus()
            app._clipboard = "P1 line\nsecond"
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return widget.value

    assert asyncio.run(_drive()) == "aP1 lineb"


def test_r_paste_29_3_right_click_empty_box_pastes(tmp_path: Path) -> None:
    """R-PASTE.29/3 (LinuxH): a right-click in an empty box pastes the first line."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        async for app, pilot, widget in _one_box_app("input"):
            app._clipboard = "P1 line\nsecond"
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return widget.value

    assert asyncio.run(_drive()) == "P1 line"


def test_r_paste_30_1_right_click_multi_line_pastes_all(tmp_path: Path) -> None:
    """R-PASTE.30/1 (LinuxH): a right-click pastes all of the text at the cursor."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        async for app, pilot, widget in _one_box_app("textarea"):
            widget.text = "ab"
            widget.selection = ((0, 1), (0, 1))
            widget.focus()
            app._clipboard = "P1 line\nsecond"
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return widget.text

    assert asyncio.run(_drive()) == "aP1 line\nsecondb"


def test_r_paste_9_4_write_failure_warning_after_right_click_copy(tmp_path: Path) -> None:
    """R-PASTE.9/4 (LinuxH): the warning after a right-click copy, both classes."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            box.value = "AAAA-BBBB"
            box.selection = (0, 4)
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            await pilot.pause()
            return notices

    notices = asyncio.run(_drive())
    warnings = [n for n in notices if n[0] == "warning"]
    assert len(warnings) == 1, notices
    assert warnings[0][1] == WRITE_FAIL_WARNING, notices


def test_r_paste_10_2_warning_line_per_failed_right_click_copy(tmp_path: Path) -> None:
    """R-PASTE.10/2 (LinuxH): ≥ 1 WARNING per right-click copy, no copied text."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "SECRET-RC-44"
            box.selection = (0, len(box.value))
            box.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            await pilot.pause()
            remove_log_capture(records)
            return [(r[1], r[2]) for r in records]

    records = asyncio.run(_drive())
    warnings = [m for level, m in records if level == "WARNING"]
    assert warnings, records
    assert not any("SECRET-RC-44" in m for m in [m for _, m in records]), records


def test_r_paste_12_3_right_click_copy_over_limit(tmp_path: Path) -> None:
    """R-PASTE.12/3 (LinuxH): a right-click copy of P70k keeps 65,536 chars."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            osc = install_osc52_spy(app)
            await show_patch_paste(app, pilot)
            ta = app.query_one("#patch_paste_text", TextArea)
            ta.text = P70K
            ta.select_all()
            ta.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, ta)
            await pilot.pause()
            await pilot.pause()
            return len(app.clipboard), [len(r) for r in osc]

    clip_len, osc_lens = asyncio.run(_drive())
    assert clip_len == CAP, clip_len
    assert osc_lens == [CAP], osc_lens


@pytest.mark.parametrize("box_kind", ["input", "textarea"], ids=["single", "multi"])
def test_r_paste_15_6_7_one_osc52_request_for_right_click_copy(
    tmp_path: Path, box_kind: str
) -> None:
    """R-PASTE.15/6-7 (LinuxH): one OSC 52 request for a right-click copy."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            osc = install_osc52_spy(app)
            if box_kind == "input":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
                widget.value = P1
                widget.selection = (0, len(P1))
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
                widget.text = P2
                widget.select_all()
            widget.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return len(osc), osc[0] if osc else None

    count, payload = asyncio.run(_drive())
    assert count == 1, (count, payload)
    assert payload == (P1 if box_kind == "input" else P2), payload


def test_r_tui_043_6_5_right_click_no_selection_pastes_app_clipboard(
    tmp_path: Path,
) -> None:
    """R-TUI-043.6/5 (LinuxH): a right-click with no selection pastes the app clipboard."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box_a = app.query_one("#a2l_tags_filter_input", Input)
            box_a.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box_a)
            await pilot.pause()
            a_value = box_a.value
            await show_patch_paste(app, pilot)
            box_m = app.query_one("#patch_paste_text", TextArea)
            box_m.text = ""
            box_m.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box_m)
            await pilot.pause()
            return a_value, box_m.text

    a_value, m_value = asyncio.run(_drive())
    assert a_value == "APP-TEXT", a_value
    assert m_value == "APP-TEXT", m_value


@pytest.mark.parametrize("kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_7_2_and_043_8_2_right_click_warns_and_selects(
    tmp_path: Path, kind: str
) -> None:
    """R-TUI-043.7/2 + .8/2 (LinuxH): a right-click with neither clipboard warns."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = ""
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            if kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
            widget.focus()
            await pilot.pause()
            _set_box(widget, "KEEP")
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return notices, widget.selected_text, _box(widget)

    notices, selected, value = asyncio.run(_drive())
    assert notices and notices[-1][0] == "warning" and notices[-1][1] == READ_FAIL_WARNING, notices
    assert selected == "KEEP", selected
    assert value == "KEEP", value


def test_r_tui_043_12_3_warning_line_on_right_click_no_text(tmp_path: Path) -> None:
    """R-TUI-043.12/3 (LinuxH): ≥ 1 WARNING of os_clipboard_input per right-click."""
    _assert_linuxh_headless()

    async def _drive() -> int:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            warnings = [
                r for r in records
                if r[0] == "s19_app.tui.os_clipboard_input" and r[1] == "WARNING"
            ]
            remove_log_capture(records)
            return len(warnings)

    assert asyncio.run(_drive()) >= 1


def test_r_tui_043_13_2_no_clipboard_text_in_log_on_right_click(tmp_path: Path) -> None:
    """R-TUI-043.13/2 (LinuxH arm): right-click paste/copy leak nothing to the log."""
    _assert_linuxh_headless()

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
            app._clipboard = "SECRET-TEXT-45"
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            box.value = "SECRET-COPY-46"
            box.selection = (0, len(box.value))
            await pilot.pause()
            await right_click_app_route(app, pilot, box)
            await pilot.pause()
            remove_log_capture(records)
            return [m for _, _, m in records]

    messages = asyncio.run(_drive())
    assert not any("SECRET-TEXT-45" in m for m in messages), messages
    assert not any("SECRET-COPY-46" in m for m in messages), messages


def test_r_tui_044_2_6_right_click_paste_capped(tmp_path: Path) -> None:
    """R-TUI-044.2/6 (LinuxH): a right-click paste of P70k → 65,536 chars each."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = P70K
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box_a = app.query_one("#a2l_tags_filter_input", Input)
            box_a.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box_a)
            await pilot.pause()
            a_len = len(box_a.value)
            await show_patch_paste(app, pilot)
            box_m = app.query_one("#patch_paste_text", TextArea)
            box_m.text = ""
            box_m.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, box_m)
            await pilot.pause()
            return a_len, len(box_m.text)

    a_len, m_len = asyncio.run(_drive())
    assert a_len == CAP and m_len == CAP, (a_len, m_len)


# ---------------------------------------------------------------------------
# LinuxH timing (R-TUI-043.10.1/3-4, R-PASTE.11/3, R-PASTE.27/3, R-PASTE.31/3-4)
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_10_1_3_4_linux_ctrl_v_ends_within_typed_key_time(
    tmp_path: Path, box_kind: str
) -> None:
    """R-TUI-043.10.1/3-4 (LinuxH): median Ctrl+V end ≤ typed-key time + bound."""
    _assert_linuxh_headless()

    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = P1000
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
            widget.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, widget, app)
            samples = []
            for _ in range(10):
                _set_box(widget, "")
                await pilot.pause()
                start = time.monotonic()
                await pilot.press("ctrl+v")
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.005)
                    await pilot.pause()
                    if P1000[:10] in _box(widget):
                        break
                samples.append(time.monotonic() - start)
            samples.sort()
            median = samples[len(samples) // 2]
            return key_time, median

    key_time, median = asyncio.run(_drive())
    assert median <= report_margin(
        f"r_tui_043_10_1_{box_kind}", median, key_time + timing_bound(0.1)
    ), (key_time, median)


@pytest.mark.serial_timing
def test_r_paste_11_3_linux_copy_ends_within_typed_key_time(tmp_path: Path) -> None:
    """R-PASTE.11/3 (LinuxH): median time to the write failure warning ≤ bound."""
    _assert_linuxh_headless()

    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, box, app)
            samples = []
            for k in range(10):
                box.value = f"C{k}"
                box.selection = (0, len(box.value))
                await pilot.pause()
                before = len(notices)
                start = time.monotonic()
                await pilot.press("ctrl+c")
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.005)
                    await pilot.pause()
                    if len(notices) > before:
                        break
                samples.append(time.monotonic() - start)
            samples.sort()
            return key_time, samples[len(samples) // 2]

    key_time, median = asyncio.run(_drive())
    assert median <= report_margin("r_paste_11_3", median, key_time + timing_bound(0.1)), (key_time, median)


@pytest.mark.serial_timing
def test_r_paste_27_3_linux_right_click_copy_ends_within_typed_key_time(
    tmp_path: Path,
) -> None:
    """R-PASTE.27/3 (LinuxH): median right-click copy end ≤ typed-key time + bound."""
    _assert_linuxh_headless()

    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, box, app)
            samples = []
            for k in range(10):
                box.value = f"C{k}"
                box.selection = (0, len(box.value))
                await pilot.pause()
                before = len(notices)
                start = time.monotonic()
                await right_click_app_route(app, pilot, box)
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.005)
                    await pilot.pause()
                    if len(notices) > before:
                        break
                samples.append(time.monotonic() - start)
            samples.sort()
            return key_time, samples[len(samples) // 2]

    key_time, median = asyncio.run(_drive())
    assert median <= report_margin("r_paste_27_3", median, key_time + timing_bound(0.1)), (key_time, median)


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_31_3_4_linux_right_click_paste_ends_within_typed_key_time(
    tmp_path: Path, box_kind: str
) -> None:
    """R-PASTE.31/3-4 (LinuxH): median right-click paste end ≤ typed-key time + bound."""
    _assert_linuxh_headless()

    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = P1000
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
            widget.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, widget, app)
            samples = []
            for _ in range(10):
                _set_box(widget, "")
                await pilot.pause()
                start = time.monotonic()
                await right_click_app_route(app, pilot, widget)
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.005)
                    await pilot.pause()
                    if P1000[:10] in _box(widget):
                        break
                samples.append(time.monotonic() - start)
            samples.sort()
            return key_time, samples[len(samples) // 2]

    key_time, median = asyncio.run(_drive())
    assert median <= report_margin(
        f"r_paste_31_{box_kind}", median, key_time + timing_bound(0.1)
    ), (key_time, median)


# ---------------------------------------------------------------------------
# Censuses (R-TUI-044.1/18, R-PASTE.18/8, R-PASTE.19/1, R-PASTE.33/1)
# ---------------------------------------------------------------------------


def _census_text_box_constructions() -> dict:
    """AST census of the text-box constructions in ``s19_app/`` (the shape of
    ``evidence-e1/i1a-census.py`` part A): 40 ``OsClipboardInput``, 6
    ``CappedTextArea`` + 1 ``JsonHighlightTextArea`` subclass (7 multi-line
    boxes), 0 stock ``Input``, 0 **editable** stock ``TextArea`` (the
    read-only ``#patch_json_view`` is excluded, as CTX-PASTE says it is not
    a multi-line box and is Inc 1b's)."""
    import ast

    from s19_app.tui import os_clipboard_input  # noqa: F401  (package anchor)

    root = Path(os_clipboard_input.__file__).resolve().parent.parent
    counts = {"OsClipboardInput": 0, "CappedTextArea": 0, "JsonHighlightTextArea": 0,
              "Input": 0, "TextArea": 0, "sites": []}

    def _kw(node: ast.Call, name: str) -> bool:
        for kw in node.keywords:
            if kw.arg == name:
                return isinstance(kw.value, ast.Constant) and kw.value.value is True
        return False

    for path in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name == "TextArea" and _kw(node, "read_only"):
                    continue  # the read-only JSON view is not a text box
                if name in ("OsClipboardInput", "CappedTextArea", "JsonHighlightTextArea", "Input", "TextArea"):
                    counts[name] += 1
                    counts["sites"].append(f"{path.name}:{node.lineno}")
    return counts


def test_r_tui_044_1_18_every_single_line_box_is_os_clipboard_input() -> None:
    """R-TUI-044.1/18: 0 stock ``Input``; every single-line box an ``OsClipboardInput``."""
    counts = _census_text_box_constructions()
    assert counts["OsClipboardInput"] == 40, counts
    assert counts["Input"] == 0, counts


def test_r_paste_18_8_every_multi_line_box_is_capped_text_area() -> None:
    """R-PASTE.18/8: 0 editable stock ``TextArea``; 7 multi-line boxes capped."""
    counts = _census_text_box_constructions()
    assert counts["CappedTextArea"] + counts["JsonHighlightTextArea"] == 7, counts
    assert counts["TextArea"] == 0, counts


def test_r_paste_19_1_and_33_1_every_text_box_is_the_two_classes() -> None:
    """R-PASTE.19/1 + .33/1: 47/47 text boxes are the two clipboard classes."""
    counts = _census_text_box_constructions()
    assert counts["OsClipboardInput"] == 40, counts
    assert counts["CappedTextArea"] + counts["JsonHighlightTextArea"] == 7, counts
    assert counts["Input"] == 0, counts
    assert counts["TextArea"] == 0, counts


# ---------------------------------------------------------------------------
# R-PASTE.20/1 — the Windows workflow, read as text
# ---------------------------------------------------------------------------


def test_r_paste_20_1_windows_workflow_runs_os_clipboard_tests() -> None:
    """R-PASTE.20/1 (static): the pinned ``clipboard-windows.yml`` shape."""
    from pathlib import Path as _Path

    from tests.test_suite_hygiene import _script_injections, _workflow_jobs

    repo = _Path(__file__).resolve().parents[1]
    workflow = repo / ".github" / "workflows" / "clipboard-windows.yml"
    text = workflow.read_text(encoding="utf-8")
    jobs = _workflow_jobs(text)
    assert list(jobs) == ["clipboard-windows"], jobs
    # runs-on: windows-latest
    assert any("runs-on: windows-latest" in line for line in jobs["clipboard-windows"]), jobs
    # triggers: workflow_dispatch, push, pull_request (no branch filter)
    assert "workflow_dispatch:" in text
    assert "push:" in text
    assert "pull_request:" in text
    assert "branches:" not in text
    for needle in (
        "s19_app/tui/os_clipboard_input.py",
        "s19_app/tui/capped_text_area.py",
        "tests/support/b103_clipboard.py",
        "tests/test_b103_clipboard_windows.py",
        "tests/test_b103_clipboard_matrix.py",
        ".github/workflows/clipboard-windows.yml",
    ):
        assert needle in text, needle
    assert "permissions:\n  contents: read" in text.replace("\r\n", "\n")
    assert "persist-credentials: false" in text
    assert "tests/test_b103_clipboard_windows.py" in text
    assert "tests/test_b103_clipboard_matrix.py" in text
    assert _script_injections(text) == []
    assert "secrets." not in text
    assert "upload-artifact" not in text
    assert "pull_request_target" not in text
    assert "workflow_run" not in text


# ---------------------------------------------------------------------------
# R-PASTE.21 — the isolation guard predicate and the suite guard
# ---------------------------------------------------------------------------


def test_r_paste_21_1_windows_not_github_hosted_stops_before_open() -> None:
    """R-PASTE.21/1 (a/b/c): the predicate fails before any open."""
    from tests.support.b103_clipboard import clipboard_isolated

    ok, reason = clipboard_isolated(
        "windows",
        environ={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"},
        platform="win32",
        account="runneradmin",
    )
    assert ok is False and "RUNNER_ENVIRONMENT='self-hosted'" == reason, (ok, reason)

    ok, reason = clipboard_isolated(
        "windows",
        environ={"GITHUB_ACTIONS": "true"},
        platform="win32",
        account="runneradmin",
    )
    assert ok is False and "RUNNER_ENVIRONMENT" in reason, (ok, reason)

    ok, reason = clipboard_isolated(
        "windows",
        environ={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
        platform="win32",
        account="username_subject",
    )
    assert ok is False and "account='username_subject'" == reason, (ok, reason)


def test_r_paste_21_2_x_display_session_did_not_start_stops() -> None:
    """R-PASTE.21/2 (LinuxH): a DISPLAY the session did not start fails."""
    from tests.support.b103_clipboard import clipboard_isolated

    ok, reason = clipboard_isolated(
        "x", environ={"DISPLAY": ":99"}, platform="linux"
    )
    assert ok is False and "session" in reason, (ok, reason)


def test_r_paste_21_3_isolated_clipboard_lets_the_test_go_on() -> None:
    """R-PASTE.21/3: the isolated term holds on a hosted runner."""
    from tests.support.b103_clipboard import clipboard_isolated

    ok, reason = clipboard_isolated(
        "windows",
        environ={"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"},
        platform="win32",
        account="runneradmin",
    )
    assert ok is True and reason == "", (ok, reason)


def test_r_paste_21_4_outside_clipboard_files_fails_before_open(pytester) -> None:
    """R-PASTE.21/4 (LinuxH pytester): the suite guard fails (``failed``, not
    ``error``) a non-isolated Windows host reaching the OS boundary."""
    _assert_linuxh_headless()
    repo = Path(__file__).resolve().parents[1]
    pytester.makeconftest(
        "import os\n"
        "os.environ['B103_HOST_PLATFORM'] = 'win32'\n"
        "os.environ['GITHUB_ACTIONS'] = 'true'\n"
        "os.environ['RUNNER_ENVIRONMENT'] = 'self-hosted'\n"
        "pytest_plugins = ['tests.conftest']\n"
    )
    (pytester.path / "test_clip.py").write_text(
        "import sys\n"
        "def test_drive():\n"
        "    import asyncio\n"
        "    from s19_app.tui.app import S19TuiApp\n"
        "    from s19_app.tui.os_clipboard_input import OsClipboardInput\n"
        "    async def _d():\n"
        "        app = S19TuiApp(base_dir=None)\n"
        "        async with app.run_test() as pilot:\n"
        "            box = app.query_one(OsClipboardInput)\n"
        "            box.value = 'AAAA'\n"
        "            box.selection = (0, 4)\n"
        "            box.focus()\n"
        "            await pilot.pause()\n"
        "            await pilot.press('ctrl+c')\n"
        "            await pilot.pause()\n"
        "    asyncio.run(_d())\n",
        encoding="utf-8",
    )
    import os as _os

    previous = _os.environ.get("PYTHONPATH")
    _os.environ["PYTHONPATH"] = str(repo) + _os.pathsep + (previous or "")
    try:
        result = pytester.runpytest_subprocess("-p", "no:cacheprovider")
    finally:
        if previous is None:
            _os.environ.pop("PYTHONPATH", None)
        else:
            _os.environ["PYTHONPATH"] = previous
    result.assert_outcomes(failed=1)
    assert "OS clipboard not isolated:" in result.stdout.str()


# ---------------------------------------------------------------------------
# R-PASTE.22/1, R-PASTE.23/1-2 — the probe skip / fail (LinuxH pytester)
# ---------------------------------------------------------------------------


def _probe_pytester(pytester, result: tuple, *, probe_test: bool = False) -> object:
    repo = Path(__file__).resolve().parents[1]
    standalone = f"({result[0]!r}, {result[1]!r})"
    pytester.makeconftest(
        "import os\n"
        "os.environ['B103_HOST_PLATFORM'] = 'win32'\n"
        "os.environ['GITHUB_ACTIONS'] = 'true'\n"
        "os.environ['RUNNER_ENVIRONMENT'] = 'github-hosted'\n"
        "import tests.support.b103_clipboard as sc\n"
        f"sc._probe_once = lambda: {standalone}\n"
        "sc._probe_cache = None\n"
        "sc._logged_account = lambda: 'runneradmin'\n"
    )
    if probe_test:
        (pytester.path / "test_probe.py").write_text(
            "from tests.support.b103_clipboard import clipboard_probe\n"
            "def test_runner_clipboard_probe():\n"
            "    import pytest\n"
            "    usable, res = clipboard_probe()\n"
            "    if not usable:\n"
            "        pytest.fail(f'runner clipboard unusable: {res}')\n",
            encoding="utf-8",
        )
    else:
        (pytester.path / "test_win.py").write_text(
            "from tests.support.b103_clipboard import os_clipboard_ready\n"
            "def test_depends_on_os_clipboard(os_clipboard_ready):\n"
            "    assert True\n",
            encoding="utf-8",
        )
    import os as _os

    previous = _os.environ.get("PYTHONPATH")
    _os.environ["PYTHONPATH"] = str(repo) + _os.pathsep + (previous or "")
    try:
        return pytester.runpytest_subprocess("-p", "no:cacheprovider", "-rs")
    finally:
        if previous is None:
            _os.environ.pop("PYTHONPATH", None)
        else:
            _os.environ["PYTHONPATH"] = previous


def test_r_paste_22_1_failed_probe_skips_os_clipboard_tests(pytester) -> None:
    """R-PASTE.22/1 (LinuxH): a failed probe skips with the exact reason."""
    _assert_linuxh_headless()
    result = _probe_pytester(pytester, (False, "win32 write ok, PowerShell read ''"))
    result.assert_outcomes(skipped=1)
    assert "runner clipboard unusable: win32 write ok, PowerShell read ''" in result.stdout.str()


def test_r_paste_23_1_failed_probe_fails_the_probe_test(pytester) -> None:
    """R-PASTE.23/1 (LinuxH): a failed probe fails the probe test with the message."""
    _assert_linuxh_headless()
    result = _probe_pytester(pytester, (False, "win32 write ok, PowerShell read ''"), probe_test=True)
    result.assert_outcomes(failed=1)
    assert "runner clipboard unusable: win32 write ok, PowerShell read ''" in result.stdout.str()


def test_r_paste_23_2_passing_probe_passes_the_probe_test(pytester) -> None:
    """R-PASTE.23/2 (LinuxH): a passing probe passes the probe test."""
    _assert_linuxh_headless()
    result = _probe_pytester(
        pytester, (True, "win32 write ok, PowerShell read 'b103-probe-0123'"), probe_test=True
    )
    result.assert_outcomes(passed=1)


# ---------------------------------------------------------------------------
# R-PASTE.36/1 — the redaction gate scans the batch-103 folder
# ---------------------------------------------------------------------------


def test_r_paste_36_1_redaction_gate_scans_batch_103_and_names_planted_leaks(
    tmp_path: Path,
) -> None:
    """R-PASTE.36/1 (LinuxH): ``_redaction_roots`` covers both batch folders and
    names the planted batch-103 leaks."""
    from tests.test_suite_hygiene import (
        _PLANTED_LEAKS,
        _local_identity_names,
        _redaction_hits,
        _redaction_roots,
    )

    shape = tmp_path / "shape"
    batch103 = shape / ".dev-flow" / "2026-11-05-batch-103" / "inc-1a"
    batch103.mkdir(parents=True)
    (batch103 / "x.md").write_text(
        _PLANTED_LEAKS["lan address"] + "\n" + _PLANTED_LEAKS["posix home path outside the runner image"] + "\n",
        encoding="utf-8",
    )
    roots = _redaction_roots(shape)
    assert roots == [
        shape / ".dev-flow" / "2026-11-01-batch-101",
        shape / ".dev-flow" / "2026-11-05-batch-103",
    ], roots
    hits = _redaction_hits(shape / ".dev-flow" / "2026-11-05-batch-103", _local_identity_names())
    named = {hit.split(": ")[1] for hit in hits}
    assert "lan address" in named and "posix home path outside the runner image" in named, hits


# ---------------------------------------------------------------------------
# R-TUI-043.5/3 — a terminal paste replaces the selection (both classes)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_5_3_terminal_paste_replaces_selection(tmp_path: Path, box_kind: str) -> None:
    """R-TUI-043.5/3 (LinuxH): ``AAAA`` selected + terminal paste ``ZZ`` → ``ZZ-BBBB``."""
    _assert_linuxh_headless()

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
                widget.focus()
                await pilot.pause()
                widget.value = "AAAA-BBBB"
                widget.selection = (0, 4)
            else:
                await show_patch_paste(app, pilot)
                widget = app.query_one("#patch_paste_text", TextArea)
                widget.focus()
                widget.text = "AAAA-BBBB"
                widget.selection = ((0, 0), (0, 4))
            await pilot.pause()
            await terminal_paste(app, "ZZ")
            await pilot.pause()
            return _box(widget)

    assert asyncio.run(_drive()) == "ZZ-BBBB"


# ---------------------------------------------------------------------------
# R-PASTE.34/6 — a pasted NUL is kept (its consumer still refuses the path)
# ---------------------------------------------------------------------------


def test_r_paste_34_6_pasted_nul_kept_consumer_refuses(tmp_path: Path) -> None:
    """R-PASTE.34/6 (LinuxH): a NUL pasted into ``#flow_ref`` stays and Add refuses."""
    _assert_linuxh_headless()
    from tests.b97_fixtures import flow_project, open_flow_builder

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            await flow_project(app)
            panel = await open_flow_builder(app, pilot)
            ref = app.query_one("#flow_ref", Input)
            ref.focus()
            await pilot.pause()
            await terminal_paste(app, "x\x00y.s19")
            await pilot.pause()
            return ref.value

    value = asyncio.run(_drive())
    assert value == "x\x00y.s19", repr(value)


# ---------------------------------------------------------------------------
# Unfocused right-click (R-PASTE.25/3, .26/3, .29/2, .29/4, .30/2)
# ---------------------------------------------------------------------------


async def _unfocus(app, pilot) -> None:
    other = app.query_one("#other", Button)
    await pilot.click(other)
    await pilot.pause()


def test_r_paste_25_3_and_26_3_multi_line_unfocused_right_click_copies(
    tmp_path: Path,
) -> None:
    """R-PASTE.25/3 + .26/3 (LinuxH): an unfocused Box 2 copies the selection it shows."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        async for app, pilot, widget in _one_box_app("textarea"):
            app._clipboard = "BEFORE"
            widget.text = "AAAA-BBBB"
            widget.selection = ((0, 0), (0, 4))
            widget.focus()
            await pilot.pause()
            await _unfocus(app, pilot)
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return app.clipboard, widget.text, widget.selection, widget.has_focus

    clip, value, selection, focused = asyncio.run(_drive())
    assert clip == "AAAA", clip
    assert value == "AAAA-BBBB", value
    assert tuple(selection) == ((0, 0), (0, 4)), selection
    assert focused is True


def test_r_paste_29_2_unfocused_single_line_pastes_at_cursor(tmp_path: Path) -> None:
    """R-PASTE.29/2 (LinuxH): an unfocused Box 1 pastes at its cursor, copies nothing."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        async for app, pilot, widget in _one_box_app("input"):
            widget.value = "ab"
            widget.selection = (2, 2)  # cursor at the end
            widget.focus()
            app._clipboard = "P1 line\nsecond"
            await pilot.pause()
            await _unfocus(app, pilot)
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return widget.value, widget.has_focus, app.clipboard

    value, focused, clip = asyncio.run(_drive())
    assert value == "abP1 line", value
    assert focused is True
    assert clip == "P1 line\nsecond", clip


def test_r_paste_29_4_blur_back_to_back_pastes_and_copies_nothing(
    tmp_path: Path,
) -> None:
    """R-PASTE.29/4 (LinuxH): a left press on #other then a right press on the
    box back to back pastes at the cursor and copies nothing."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        async for app, pilot, widget in _one_box_app("input"):
            widget.value = "ab"
            widget.selection = (2, 2)
            widget.focus()
            app._clipboard = "P1 line\nsecond"
            await pilot.pause()
            other = app.query_one("#other", Button)
            await pilot.click(other)
            region = widget.region
            x = region.x + min(2, max(0, region.width - 1))
            y = region.y
            down = events.MouseDown(widget=widget, x=x, y=y, button=3, delta_x=0, delta_y=0, shift=False, meta=False, ctrl=False, screen_x=x, screen_y=y, style=None)
            up = events.MouseUp(widget=widget, x=x, y=y, button=3, delta_x=0, delta_y=0, shift=False, meta=False, ctrl=False, screen_x=x, screen_y=y, style=None)
            app.post_message(down)
            app.post_message(up)
            await pilot.pause()
            await pilot.pause()
            return widget.value, app.clipboard

    value, clip = asyncio.run(_drive())
    assert value == "abP1 line", value
    assert clip == "P1 line\nsecond", clip


def test_r_paste_30_2_unfocused_multi_line_pastes_at_cursor(tmp_path: Path) -> None:
    """R-PASTE.30/2 (LinuxH): an unfocused Box 2 pastes all at its cursor."""
    _assert_linuxh_headless()

    async def _drive() -> tuple:
        async for app, pilot, widget in _one_box_app("textarea"):
            widget.text = "ab"
            widget.selection = ((0, 1), (0, 1))
            widget.focus()
            app._clipboard = "P1 line\nsecond"
            await pilot.pause()
            await _unfocus(app, pilot)
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return widget.text, widget.has_focus

    value, focused = asyncio.run(_drive())
    assert value == "aP1 line\nsecondb", value
    assert focused is True


# ---------------------------------------------------------------------------
# LinuxX arms (R-TUI-043.6/4, R-PASTE.9/3) — private Xvfb + xclip
# ---------------------------------------------------------------------------


def _require_linuxx() -> None:
    if sys.platform == "win32":
        pytest.skip("Windows only")
    if not os.environ.get("DISPLAY"):
        pytest.skip("LinuxX needs a private Xvfb DISPLAY")
    if shutil.which("xclip") is None:
        pytest.skip("LinuxX needs xclip")


def test_r_tui_043_6_4_linux_x_clipboard_is_not_read(tmp_path: Path) -> None:
    """R-TUI-043.6/4 (LinuxX): the X clipboard is not read; the app clipboard wins."""
    _require_linuxx()
    subprocess.run(
        ["xclip", "-selection", "clipboard", "-i"],
        input="X-TEXT", text=True, check=True, timeout=10.0,
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return box.value

    assert asyncio.run(_drive()) == "APP-TEXT"


def test_r_paste_9_3_linux_copy_leaves_x_clipboard(tmp_path: Path) -> None:
    """R-PASTE.9/3 (LinuxX): a copy leaves the X clipboard as it was; the warning shows."""
    _require_linuxx()
    subprocess.run(
        ["xclip", "-selection", "clipboard", "-i"],
        input="X-BEFORE", text=True, check=True, timeout=10.0,
    )

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "COPY-X"
            box.selection = (0, len(box.value))
            box.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            return [n for n in notices if n[0] == "warning"]

    warnings = asyncio.run(_drive())
    read_back = subprocess.run(
        ["xclip", "-selection", "clipboard", "-o"],
        capture_output=True, text=True, timeout=10.0,
    ).stdout
    assert read_back == "X-BEFORE", repr(read_back)
    assert warnings and warnings[0][1] == WRITE_FAIL_WARNING, warnings


# ---------------------------------------------------------------------------
# R-TUI-044.2/8 — the Win32 read asks for at most GlobalSize // 2 chars
# (partial: it calls the private ``_read_via_ctypes`` with a stubbed ctypes)
# ---------------------------------------------------------------------------


def test_r_tui_044_2_8_win32_read_bounded_by_global_size(monkeypatch) -> None:
    """R-TUI-044.2/8 (LinuxH unit, partial): ``wstring_at(pointer, 1000)`` once."""
    import sys as _sys

    from s19_app.tui import os_clipboard_input as mod

    recorded = {}

    class _FakeWintypes:
        HWND = 1
        UINT = 2
        BOOL = 3
        HANDLE = 4
        HGLOBAL = 5

    def _open_clipboard(hwnd):
        recorded["open"] = True
        return 1

    def _close_clipboard():
        return 1

    def _get_clipboard_data(fmt):
        return 0x1234

    def _global_lock(handle):
        return 0xABCD

    def _global_unlock(handle):
        return 1

    def _global_size(handle):
        return 2000

    # Plain functions (not bound methods), so the product's
    # ``OpenClipboard.argtypes = ...`` assignments land (bound methods
    # reject attribute assignment).
    fake_ctypes = type(sys)("fake_ctypes")
    fake_ctypes.windll = type(sys)("windll")
    fake_ctypes.windll.user32 = type(sys)("user32")
    fake_ctypes.windll.user32.OpenClipboard = _open_clipboard
    fake_ctypes.windll.user32.CloseClipboard = _close_clipboard
    fake_ctypes.windll.user32.GetClipboardData = _get_clipboard_data
    fake_ctypes.windll.kernel32 = type(sys)("kernel32")
    fake_ctypes.windll.kernel32.GlobalLock = _global_lock
    fake_ctypes.windll.kernel32.GlobalUnlock = _global_unlock
    fake_ctypes.windll.kernel32.GlobalSize = _global_size
    fake_ctypes.wintypes = _FakeWintypes()
    fake_ctypes.c_size_t = int
    fake_ctypes.c_void_p = int
    fake_ctypes.memmove = lambda *a: None
    fake_ctypes.HGLOBAL = 5

    def _wstring_at(pointer, size=None):
        recorded["wstring_at"] = (pointer, size)
        return "x" * (size if size is not None else 1)

    fake_ctypes.wstring_at = _wstring_at

    monkeypatch.setitem(_sys.modules, "ctypes", fake_ctypes)
    monkeypatch.setattr(_sys, "platform", "win32")

    text = mod._read_via_ctypes()
    assert recorded["wstring_at"] == (0xABCD, 1000), recorded
    assert text == "x" * 1000

