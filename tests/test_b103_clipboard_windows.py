"""Batch-103 Inc 1a clipboard Windows — the WinCI cases (G-T2).

Summary:
    The OS-clipboard arms that run only on the hosted Windows runner
    (``.github/workflows/clipboard-windows.yml``). Every test requests the
    ``os_clipboard_ready`` fixture: off Windows it is skipped with the reason
    ``Windows only``; on a non-isolated Windows host it fails before any open
    (R-PASTE.21); on a hosted runner whose probe failed it is skipped with
    ``runner clipboard unusable: <probe result>`` (R-PASTE.22). The probe
    test itself (``test_runner_clipboard_probe``) FAILS on a failed probe
    (R-PASTE.23) and is collected from the workflow's run line (R-PASTE.20/1).

    Each case's objective, preconditions and expected result are
    ``02-test-cases.md``; the assertions below use the module's Windows
    helpers (Other-program write/read, Own write/read, the held clipboard,
    the process spy) so the product itself produces every asserted value.

Dependencies:
    Uses:
        - ``tests.support.b103_clipboard`` (isolation, probe, Win32 helpers)
        - ``s19_app.tui.os_clipboard_input`` / ``capped_text_area``
    Used by:
        - the hosted ``clipboard-windows`` CI job
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest
from textual.widgets import Input, TextArea

from s19_app.tui.app import S19TuiApp
from tests.support.b103_clipboard import (
    CAP,
    P1000,
    P2,
    P2_ESC,
    P_CTRL_L,
    P_CTRL_MW,
    P_CTRL_W,
    P70K,
    P1,
    READ_FAIL_WARNING,
    WRITE_FAIL_WARNING,
    _box,
    _box_lines,
    _set_box,
    clipboard_sequence_number,
    install_notice_capture,
    install_process_spy,
    os_clipboard_ready,
    other_program_read,
    other_program_write,
    own_read,
    right_click_app_route,
    show_patch_paste,
    terminal_paste,
    typed_key_time,
)
from tests.support.timing import report_margin, timing_bound


@pytest.fixture(autouse=True)
def _windows_only() -> None:
    """Skip every test in this file off Windows at setup (E3A-28): the
    collection stays unchanged (the probe test is still collected by the
    workflow's run line), and on WinCI the per-test ``os_clipboard_ready``
    fixture then applies the isolation guard and the probe skip."""
    from tests.support.b103_clipboard import host_platform

    if host_platform() != "win32":
        pytest.skip("Windows only")


async def _drive_real_app(tmp_path: Path, screen_key: str):
    app = S19TuiApp(base_dir=tmp_path)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen(screen_key)
        for _ in range(4):
            await pilot.pause()
        yield app, pilot


async def _box_a(tmp_path: Path):
    async for app, pilot in _drive_real_app(tmp_path, "a2l"):
        yield app, pilot, app.query_one("#a2l_tags_filter_input", Input)


async def _box_m(tmp_path: Path):
    async for app, pilot in _drive_real_app(tmp_path, "patch"):
        await show_patch_paste(app, pilot)
        widget = app.query_one("#patch_paste_text", TextArea)
        widget.text = ""
        widget.focus()
        await pilot.pause()
        yield app, pilot, widget


def _select(widget: object) -> None:
    if isinstance(widget, TextArea):
        widget.select_all()
    else:
        widget.selection = (0, len(widget.value or ""))


def _median(samples: list) -> float:
    samples = sorted(samples)
    return samples[len(samples) // 2]


async def _wait_for_box(pilot, widget: object, expected: str, timeout: float = 10.0) -> float:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if expected[:10] in _box(widget):
            return time.monotonic() - start
        await asyncio.sleep(0.005)
        await pilot.pause()
    raise AssertionError(f"box never held {expected!r}; got {_box(widget)!r}")


# ---------------------------------------------------------------------------
# The probe test (R-PASTE.23/2, R-PASTE.22/2)
# ---------------------------------------------------------------------------


def test_runner_clipboard_probe() -> None:
    """R-PASTE.23/2 + R-PASTE.22/2: the hosted runner's clipboard probe.

    Fails (never skips) with ``runner clipboard unusable: <probe result>``
    when the probe cannot round-trip its nonce, so a green job can never
    mean "all OS clipboard tests skipped" (orchestrator ruling D-7 B)."""
    from tests.support.b103_clipboard import clipboard_probe, require_isolated_clipboard

    require_isolated_clipboard("windows")
    usable, result = clipboard_probe()
    if not usable:
        pytest.fail(f"runner clipboard unusable: {result}")


# ---------------------------------------------------------------------------
# Paste: time and fallback (WinCI)
# ---------------------------------------------------------------------------


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_10_1_1_2_ctrl_v_ends_within_typed_key_time(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.10.1/1-2 (WinCI): median Ctrl+V of P1000 ≤ typed-key time + bound."""
    other_program_write(P1000)

    async def _drive() -> float:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, widget, app)
            samples = []
            for _ in range(10):
                _set_box(widget, "")
                await pilot.pause()
                start = time.monotonic()
                await pilot.press("ctrl+v")
                samples.append(await _wait_for_box(pilot, widget, P1000))
            return key_time, _median(samples)

    key_time, median = asyncio.run(_drive())
    bound = timing_bound(0.1)
    assert median <= key_time + report_margin(f"r_tui_043_10_1_{box_kind}", median, key_time + bound), (key_time, median)


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_10_1_5_6_no_text_no_powershell(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.10.1/5-6 (WinCI): a file-drop/bitmap clipboard → 0 starts."""
    from s19_app.tui import os_clipboard_input as mod

    for arm in ("file-drop", "bitmap"):
        _write_nontext_clipboard(arm)
        started = install_process_spy(mod)

        async def _drive() -> int:
            app = S19TuiApp(base_dir=tmp_path)
            app._clipboard = "APP-TEXT"
            async with app.run_test(size=(160, 48)) as pilot:
                await pilot.pause()
                if box_kind == "a":
                    app.action_show_screen("a2l")
                    for _ in range(4):
                        await pilot.pause()
                    widget = app.query_one("#a2l_tags_filter_input", Input)
                else:
                    app.action_show_screen("patch")
                    for _ in range(4):
                        await pilot.pause()
                    widget = app.query_one("#patch_paste_text", TextArea)
                    widget.text = ""
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+v")
                await pilot.pause()
                return len(widget.value) if box_kind == "a" else len(widget.text)

        n = asyncio.run(_drive())
        assert n == len("APP-TEXT"), n
        assert started == [], started


def _write_nontext_clipboard(arm: str) -> None:
    """Write a file-drop list or a bitmap (no ``CF_UNICODETEXT``) with the
    test's own Win32 code (R-TUI-043.10.1/5-6, R-PASTE.31/5-6)."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    fmt = 15 if arm == "file-drop" else 8  # CF_HDROP / CF_DIB
    data = b"\x00" * 32
    handle = kernel32.GlobalAlloc(0x0002, len(data))
    pointer = kernel32.GlobalLock(handle)
    ctypes.memmove(pointer, data, len(data))
    kernel32.GlobalUnlock(handle)
    assert user32.OpenClipboard(None)
    try:
        user32.EmptyClipboard()
        assert user32.SetClipboardData(fmt, handle)
    finally:
        user32.CloseClipboard()


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_10_2_1_2_held_clipboard_paste_ends_within_2_5(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.10.2/1-2 (WinCI): a held clipboard paste ends ≤ 2.5 s."""
    _held = _hold_clipboard(8.0)

    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                app.action_show_screen("patch")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#patch_paste_text", TextArea)
            widget.focus()
            await pilot.pause()
            start = time.monotonic()
            await pilot.press("ctrl+v")
            elapsed = await _wait_for_box(pilot, widget, "APP-TEXT")
            if box_kind == "a":
                # C5: settle the _apply_filter debounce (0.15 s) while the a2l
                # screen is still mounted, so its timer callback cannot fire
                # during teardown against the unmounted #a2l_tags_list
                # (NoMatches on Screen('_default')).
                await asyncio.sleep(0.25)
                await pilot.pause()
            return elapsed

    try:
        elapsed = asyncio.run(_drive())
    finally:
        _held["release"].set()
    bound = timing_bound(2.5)
    assert elapsed <= report_margin(f"r_tui_043_10_2_{box_kind}", elapsed, bound), elapsed


def _hold_clipboard(seconds: float) -> dict:
    """Hold the clipboard from a separate process (never a thread of the
    test process) so a held read/write really fails cross-process.

    The child creates a message-only window (``CreateWindowExW`` with parent
    ``HWND_MESSAGE``) so the clipboard is owned by a real window, opens the
    clipboard with that ``hwnd`` and keeps it open while pumping messages
    until killed; ``release.set()`` (or the ``seconds`` fallback) kills the
    child, which makes Windows drop the hold. The parent then VERIFIES the
    hold with its own ``OpenClipboard(None)``: it must return 0 (the child
    holds the clipboard), otherwise the hold is not effective and this raises
    ``clipboard hold not effective`` (run-3 triage C4).
    """
    script = textwrap.dedent(
        """
        import ctypes
        import sys
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]

        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HANDLE, wintypes.HMODULE, ctypes.c_void_p,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND

        hinstance = kernel32.GetModuleHandleW(None)
        hwnd = user32.CreateWindowExW(
            0, "STATIC", "b103-holder", 0,
            0, 0, 0, 0, -3, None, hinstance, None,  # HWND_MESSAGE = -3
        )
        if not hwnd:
            print("WINDOW-FAILED", flush=True)
            sys.exit(1)

        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        if not user32.OpenClipboard(hwnd):
            print("OPEN-FAILED", flush=True)
            sys.exit(1)
        print("HOLDING", flush=True)

        user32.PeekMessageW.argtypes = [
            ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT,
            wintypes.UINT, wintypes.UINT,
        ]
        user32.PeekMessageW.restype = wintypes.BOOL
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = ctypes.c_ssize_t

        msg = wintypes.MSG()
        while True:
            while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            user32.Sleep(10)
        """
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    ready = proc.stdout.readline().strip()
    if ready != "HOLDING":
        proc.wait()
        raise RuntimeError(f"clipboard hold child failed to hold: {ready!r}")

    # Verify the hold cross-process before any test proceeds: this process's
    # own OpenClipboard must fail (return 0) because the child holds it. A
    # nonzero return means the hold is not effective (run-3 triage C4).
    if _open_clipboard_probe() != 0:
        proc.kill()
        proc.wait()
        raise RuntimeError(
            "clipboard hold not effective: parent OpenClipboard returned "
            "nonzero (expected 0) while the child reports HOLDING"
        )

    state = {"proc": proc, "release": threading.Event()}

    def _supervisor() -> None:
        state["release"].wait(timeout=seconds)
        if proc.poll() is None:
            proc.kill()
        proc.wait()

    threading.Thread(target=_supervisor, daemon=True).start()
    return state


def _open_clipboard_probe() -> int:
    """This process's ``OpenClipboard(None)`` BOOL (0 = held by another task).

    Used by :func:`_hold_clipboard` to verify the child really holds the
    clipboard: a nonzero return (this process could open it) closes the
    clipboard again and signals the hold is ineffective.
    """
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    result = int(user32.OpenClipboard(None))
    if result:
        user32.CloseClipboard()
    return result


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_6_2_held_clipboard_pastes_app_clipboard(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.6/2 (WinCI): a held clipboard pastes the app clipboard."""
    _held = _hold_clipboard(8.0)

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                app.action_show_screen("patch")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#patch_paste_text", TextArea)
                widget.text = ""
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return _box(widget)

    try:
        value = asyncio.run(_drive())
    finally:
        _held["release"].set()
    assert value == "APP-TEXT", value


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_6_3_empty_unicode_text_pastes_app_clipboard_no_powershell(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.6/3 (WinCI): an empty Unicode text → app clipboard, 0 starts."""
    from s19_app.tui import os_clipboard_input as mod

    _write_empty_unicode_text()
    started = install_process_spy(mod)

    async def _drive() -> tuple:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            notices = install_notice_capture(app)
            if box_kind == "a":
                app.action_show_screen("a2l")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#a2l_tags_filter_input", Input)
            else:
                app.action_show_screen("patch")
                for _ in range(4):
                    await pilot.pause()
                widget = app.query_one("#patch_paste_text", TextArea)
                widget.text = ""
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return _box(widget), [n for n in notices if n[0] == "warning"]

    value, warnings = asyncio.run(_drive())
    assert value == "APP-TEXT", value
    assert not warnings, warnings
    assert started == [], started


def _write_empty_unicode_text() -> None:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    data = b"\x00\x00"  # zero characters
    handle = kernel32.GlobalAlloc(0x0002, len(data))
    pointer = kernel32.GlobalLock(handle)
    ctypes.memmove(pointer, data, len(data))
    kernel32.GlobalUnlock(handle)
    assert user32.OpenClipboard(None)
    try:
        user32.EmptyClipboard()
        assert user32.SetClipboardData(13, handle)
    finally:
        user32.CloseClipboard()


# ---------------------------------------------------------------------------
# Paste rules (WinCI) — placement, selection, code page, log
# ---------------------------------------------------------------------------


def test_r_tui_043_4_1_single_line_inserts_first_line_at_cursor(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-TUI-043.4/1 (WinCI): ``ab`` cursor between → ``aP1 lineb``."""
    other_program_write("P1 line\nsecond")

    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.value = "ab"
            widget.focus()
            await pilot.pause()
            widget.selection = (1, 1)
            await pilot.press("ctrl+v")
            await pilot.pause()
            return widget.value

    assert asyncio.run(_drive()) == "aP1 lineb"


def test_r_tui_044_3_1_multi_line_inserts_all_at_cursor(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-TUI-044.3/1 (WinCI): ``ab`` cursor between → ``aP1 line\\nsecondb``."""
    other_program_write("P1 line\nsecond")

    async def _drive() -> str:
        async for app, pilot, widget in _box_m(tmp_path):
            widget.text = "ab"
            widget.selection = ((0, 1), (0, 1))
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return widget.text

    assert asyncio.run(_drive()) == "aP1 line\nsecondb"


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_5_1_2_ctrl_v_replaces_selection(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.5/1-2 (WinCI): ``AAAA`` selected + ``ZZ`` → ``ZZ-BBBB``."""
    other_program_write("ZZ")

    async def _drive() -> str:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            if box_kind == "a":
                widget.value = "AAAA-BBBB"
            else:
                widget.text = "AAAA-BBBB"
            widget.focus()
            await pilot.pause()
            if box_kind == "a":
                widget.selection = (0, 4)
            else:
                widget.selection = ((0, 0), (0, 4))
            await pilot.press("ctrl+v")
            await pilot.pause()
            return _box(widget)

    assert asyncio.run(_drive()) == "ZZ-BBBB"


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_11_1_code_page_characters_arrive_unchanged(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.11/1 (WinCI): P1's code points survive a Ctrl+V."""
    other_program_write(P1)

    async def _drive() -> str:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return _box(widget)

    assert asyncio.run(_drive()) == P1


def test_r_tui_043_12_2_held_clipboard_logs_warning(tmp_path: Path, os_clipboard_ready) -> None:
    """R-TUI-043.12/2 (WinCI): a held clipboard read logs ≥ 1 WARNING."""
    from tests.support.b103_clipboard import install_log_capture, remove_log_capture

    _held = _hold_clipboard(8.0)

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
            await pilot.press("ctrl+v")
            await pilot.pause()
            deadline = time.monotonic() + 5.0
            n = 0
            while time.monotonic() < deadline:
                n = sum(1 for r in records if r[0] == "s19_app.tui.os_clipboard_input" and r[1] == "WARNING")
                if n >= 1:
                    break
                await asyncio.sleep(0.005)
                await pilot.pause()
            remove_log_capture(records)
            return n

    try:
        n = asyncio.run(_drive())
    finally:
        _held["release"].set()
    assert n >= 1


def test_r_tui_043_13_1_no_clipboard_text_in_log_win(tmp_path: Path, os_clipboard_ready) -> None:
    """R-TUI-043.13/1 (WinCI arm): a paste and a copy leak nothing to the log."""
    from tests.support.b103_clipboard import install_log_capture, remove_log_capture

    other_program_write("SECRET-TEXT-42")

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            records = install_log_capture()
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
# Paste limit (WinCI)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_044_2_4_ctrl_v_of_os_text_capped(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-044.2/4 (WinCI): a 70,000-char OS text → 65,536 chars each."""
    other_program_write(P70K)

    async def _drive() -> int:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return len(_box(widget))

    assert asyncio.run(_drive()) == CAP


def test_r_tui_044_2_7_win32_read_bounded_on_no_terminator(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-TUI-044.2/7 (WinCI): a 70,000-char no-terminator block reads 65,537."""
    from s19_app.tui import os_clipboard_input as mod

    _own_write_no_terminator("x" * 70000)
    text = mod._read_via_ctypes()
    assert len(text) == 65537, len(text)

    async def _drive() -> tuple:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return len(widget.value)

    assert asyncio.run(_drive()) == CAP


def _own_write_no_terminator(text: str) -> None:
    """Write a ``CF_UNICODETEXT`` block with no terminating NUL, every unit
    up to its ``GlobalSize`` non-NUL (E3S-20)."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    data = text.encode("utf-16-le")  # no trailing NUL
    handle = kernel32.GlobalAlloc(0x0002, len(data))
    pointer = kernel32.GlobalLock(handle)
    ctypes.memmove(pointer, data, len(data))
    kernel32.GlobalUnlock(handle)
    assert user32.OpenClipboard(None)
    try:
        user32.EmptyClipboard()
        assert user32.SetClipboardData(13, handle)
    finally:
        user32.CloseClipboard()


# ---------------------------------------------------------------------------
# Unsafe paste characters (WinCI arms)
# ---------------------------------------------------------------------------


def test_r_paste_34_2_own_write_strips_single_line(tmp_path: Path, os_clipboard_ready) -> None:
    """R-PASTE.34/2 (WinCI): P-CTRL-W → ``A[13DBC``; P-CTRL-L → ``L1[2J``."""
    from tests.support.b103_clipboard import _own_write

    async def _drive() -> tuple:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.focus()
            _own_write(P_CTRL_W)
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            first = widget.value
            widget.value = ""
            _own_write(P_CTRL_L)
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return first, widget.value

    first, second = asyncio.run(_drive())
    assert first == "A[13DBC", repr(first)
    assert second == "L1[2J", repr(second)


def test_r_paste_34_4_win_right_click_strips_single_line(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.34/4 (WinCI arm): a right-click paste strips as /2."""
    from tests.support.b103_clipboard import _own_write

    async def _drive() -> tuple:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.focus()
            _own_write(P_CTRL_W)
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            first = widget.value
            widget.value = ""
            _own_write(P_CTRL_L)
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return first, widget.value

    first, second = asyncio.run(_drive())
    assert first == "A[13DBC", repr(first)
    assert second == "L1[2J", repr(second)


def test_r_paste_35_2_own_write_strips_multi_line(tmp_path: Path, os_clipboard_ready) -> None:
    """R-PASTE.35/2 (WinCI): P-CTRL-MW then P2-ESC strip to the exact lines."""
    from tests.support.b103_clipboard import _box_lines, _own_write

    async def _drive() -> tuple:
        async for app, pilot, widget in _box_m(tmp_path):
            widget.focus()
            _own_write(P_CTRL_MW)
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            first = _box_lines(widget)
            widget.text = ""
            _own_write(P2_ESC)
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return first, _box_lines(widget)

    first, second = asyncio.run(_drive())
    assert first == ["A[13DBC\tD", "E"], first
    assert second == ["L1 Ñ€[2J", "L2 漢"], second


def test_r_paste_35_4_win_right_click_strips_multi_line(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.35/4 (WinCI arm): a right-click paste strips as /2's first."""
    from tests.support.b103_clipboard import _box_lines, _own_write

    async def _drive() -> list:
        async for app, pilot, widget in _box_m(tmp_path):
            widget.focus()
            _own_write(P_CTRL_MW)
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return _box_lines(widget)

    assert asyncio.run(_drive()) == ["A[13DBC\tD", "E"]


# ---------------------------------------------------------------------------
# Copy and cut (WinCI)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_2_five_consecutive_copies_reach_other_program(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.2/1-2 (WinCI): 5/5 copies read back by PowerShell."""
    async def _drive() -> list:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            reads = []
            for k in range(1, 6):
                payload = f"COPY-{k} Ñ€" if box_kind == "a" else f"L1-{k}\nL2-{k}"
                _set_box(widget, payload)
                if box_kind == "a":
                    widget.selection = (0, len(payload))
                else:
                    widget.select_all()
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+c")
                await pilot.pause()
                await pilot.pause()
                reads.append(other_program_read())
            return reads

    reads = asyncio.run(_drive())
    expected = [f"COPY-{k} Ñ€" for k in range(1, 6)] if box_kind == "a" else [f"L1-{k}\nL2-{k}" for k in range(1, 6)]
    assert reads == expected, reads


def test_r_paste_3_win_copy_puts_selection_on_app_clipboard(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.3 (WinCI arm): Ctrl+C puts the selection on the app clipboard."""
    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.value = "COPYME-1"
            widget.selection = (0, len(widget.value))
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            return app.clipboard

    assert asyncio.run(_drive()) == "COPYME-1"


def test_r_paste_5_win_no_selection_keeps_os_clipboard(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.5 (WinCI arm): no selection → OS clipboard keeps OS-BEFORE."""
    other_program_write("OS-BEFORE")

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "BEFORE"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.action_show_screen("a2l")
            for _ in range(4):
                await pilot.pause()
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "KEEP"
            box.focus()
            await pilot.pause()
            box.selection = (4, 4)
            await pilot.press("ctrl+c")
            await pilot.pause()
            return app.clipboard

    internal = asyncio.run(_drive())
    assert internal == "BEFORE", internal
    assert other_program_read() == "OS-BEFORE"


def test_r_paste_6_win_cut_copies_selection(tmp_path: Path, os_clipboard_ready) -> None:
    """R-PASTE.6 (WinCI arm): Ctrl+X copies the selection to the OS clipboard."""
    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.value = "CUTME-1"
            widget.selection = (0, len(widget.value))
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+x")
            await pilot.pause()
            await pilot.pause()
            return app.clipboard

    internal = asyncio.run(_drive())
    assert internal == "CUTME-1", internal
    assert other_program_read() == "CUTME-1"


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_9_2_held_clipboard_write_warning(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.9/2 (WinCI): a held clipboard copy shows the write failure warning."""
    _held = _hold_clipboard(8.0)

    async def _drive() -> list:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            notices = install_notice_capture(app)
            _set_box(widget, "AAAA-BBBB")
            if box_kind == "a":
                widget.selection = (0, 4)
            else:
                widget.selection = ((0, 0), (0, 4))
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()
            return [n for n in notices if n[0] == "warning"]

    try:
        warnings = asyncio.run(_drive())
    finally:
        _held["release"].set()
    assert warnings and warnings[-1][1] == WRITE_FAIL_WARNING, warnings


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_11_1_2_copy_ends_within_typed_key_time(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.11/1-2 (WinCI): median copy end ≤ typed-key time + bound."""
    async def _drive() -> float:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, widget, app)
            samples = []
            for k in range(10):
                _set_box(widget, f"C{k}")
                _select(widget)
                await pilot.pause()
                before = clipboard_sequence_number()
                start = time.monotonic()
                await pilot.press("ctrl+c" if box_kind == "a" else "ctrl+x")
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.005)
                    await pilot.pause()
                    if clipboard_sequence_number() != before:
                        break
                samples.append(time.monotonic() - start)
            return key_time, _median(samples)

    key_time, median = asyncio.run(_drive())
    bound = timing_bound(0.1)
    assert median <= key_time + report_margin(f"r_paste_11_{box_kind}", median, key_time + bound), (key_time, median)


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_12_2_copy_over_limit_os(tmp_path: Path, os_clipboard_ready, box_kind: str) -> None:
    """R-PASTE.12/2 (WinCI): a P70k copy → 65,536 on the OS clipboard."""
    async def _drive() -> None:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            _set_box(widget, P70K)
            _select(widget)
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()

    asyncio.run(_drive())
    assert len(other_program_read()) == CAP


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_13_1_2_held_clipboard_copy_ends_within_2_5(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.13/1-2 (WinCI): a held clipboard copy warns ≤ 2.5 s."""
    _held = _hold_clipboard(8.0)

    async def _drive() -> float:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            notices = install_notice_capture(app)
            _set_box(widget, "AAAA-BBBB")
            if box_kind == "a":
                widget.selection = (0, 4)
            else:
                widget.selection = ((0, 0), (0, 4))
            widget.focus()
            await pilot.pause()
            before = len(notices)
            start = time.monotonic()
            await pilot.press("ctrl+c")
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                await asyncio.sleep(0.005)
                await pilot.pause()
                if len(notices) > before:
                    return time.monotonic() - start
            return 999.0

    try:
        elapsed = asyncio.run(_drive())
    finally:
        _held["release"].set()
    bound = timing_bound(2.5)
    assert elapsed <= report_margin(f"r_paste_13_{box_kind}", elapsed, bound), elapsed


# ---------------------------------------------------------------------------
# Held-clipboard responsiveness (WinCI) — R-PASTE.14, R-TUI-043.9
# ---------------------------------------------------------------------------


async def _held_clipboard_tick_lateness(
    app, pilot, widget, mode: str, *, right_click: bool
) -> tuple:
    """Arm tick lateness; wrap the OS read/write entry with a pass-through
    marker; fire the key or the App-route right-click and wait until the
    held-clipboard read/write ends. Returns ``(marker, lateness)``."""
    from s19_app.tui import os_clipboard_input as mod
    from tests.support.b103_clipboard import arm_tick_lateness

    marker = {"started": False, "ended": False}
    if mode == "read":
        original = mod.read_os_clipboard

        def _wrap(*args, **kwargs):
            marker["started"] = True
            try:
                return original(*args, **kwargs)
            finally:
                marker["ended"] = True

        mod.read_os_clipboard = _wrap
    else:
        original = mod.write_os_clipboard

        def _wrap(text, *args, **kwargs):
            marker["started"] = True
            try:
                return original(text, *args, **kwargs)
            finally:
                marker["ended"] = True

        mod.write_os_clipboard = _wrap
    try:
        async for lateness in arm_tick_lateness(app, marker):
            if right_click:
                await right_click_app_route(app, pilot, widget)
            else:
                await pilot.press("ctrl+v" if mode == "read" else "ctrl+c")
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline and not marker["ended"]:
                await asyncio.sleep(0.005)
                await pilot.pause()
            if not marker["ended"]:
                raise AssertionError(f"{mode} never ended against the held clipboard")
    finally:
        if mode == "read":
            mod.read_os_clipboard = original
        else:
            mod.write_os_clipboard = original
    return marker, lateness


async def _drive_box1_held_lateness(
    box_value: str, *, mode: str, right_click: bool
) -> tuple:
    """Drive Box 1 (the one-box app) through a held-clipboard read/write
    under armed tick lateness; return ``(marker, lateness)``."""
    from tests.support.b103_clipboard import _OneBoxApp

    app = _OneBoxApp("input")
    async with app.run_test(size=(80, 30)) as pilot:
        await pilot.pause()
        widget = app.query_one("#box")
        widget.focus()
        if box_value:
            _set_box(widget, box_value)
            _select(widget)
        await pilot.pause()
        return await _held_clipboard_tick_lateness(
            app, pilot, widget, mode, right_click=right_click
        )


def _assert_ticks_on_time(label: str, marker: dict, lateness: list) -> None:
    """R-PASTE.14 / R-TUI-043.9 oracle: ≥ 10 ticks fired, every tick ≤ bound."""
    assert marker["started"] is True, "clipboard read/write never started (vacuous)"
    assert len(lateness) >= 10, f"only {len(lateness)} ticks fired"
    bound = timing_bound(0.1)
    assert max(lateness) <= report_margin(label, max(lateness), bound), lateness


@pytest.mark.serial_timing
def test_r_tui_043_9_1_held_read_ctrl_v_stays_responsive(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-TUI-043.9/1 (WinCI): the screen stays responsive while a read waits on a held clipboard."""
    _held = _hold_clipboard(8.0)
    try:
        marker, lateness = asyncio.run(
            _drive_box1_held_lateness("", mode="read", right_click=False)
        )
    finally:
        _held["release"].set()
    _assert_ticks_on_time("r_tui_043_9_1", marker, lateness)


@pytest.mark.serial_timing
def test_r_paste_14_1_held_write_ctrl_c_stays_responsive(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.14/1 (WinCI): the screen stays responsive while a write waits on a held clipboard."""
    _held = _hold_clipboard(8.0)
    try:
        marker, lateness = asyncio.run(
            _drive_box1_held_lateness("AAAA-BBBB", mode="write", right_click=False)
        )
    finally:
        _held["release"].set()
    _assert_ticks_on_time("r_paste_14_1", marker, lateness)


@pytest.mark.serial_timing
def test_r_paste_14_2_held_write_right_click_stays_responsive(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.14/2 (WinCI): the screen stays responsive while a right-click write waits on a held clipboard."""
    _held = _hold_clipboard(8.0)
    try:
        marker, lateness = asyncio.run(
            _drive_box1_held_lateness("AAAA-BBBB", mode="write", right_click=True)
        )
    finally:
        _held["release"].set()
    _assert_ticks_on_time("r_paste_14_2", marker, lateness)


@pytest.mark.serial_timing
def test_r_tui_043_9_2_held_read_right_click_stays_responsive(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-TUI-043.9/2 (WinCI): the screen stays responsive while a right-click read waits on a held clipboard."""
    _held = _hold_clipboard(8.0)
    try:
        marker, lateness = asyncio.run(
            _drive_box1_held_lateness("", mode="read", right_click=True)
        )
    finally:
        _held["release"].set()
    _assert_ticks_on_time("r_tui_043_9_2", marker, lateness)


# ---------------------------------------------------------------------------
# Right-click (WinCI)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_24_1_2_five_right_click_copies(tmp_path: Path, os_clipboard_ready, box_kind: str) -> None:
    """R-PASTE.24/1-2 (WinCI): 5/5 right-click copies read back."""
    async def _drive() -> list:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            reads = []
            for k in range(1, 6):
                payload = f"RC-{k} Ñ€" if box_kind == "a" else f"RL1-{k}\nRL2-{k}"
                _set_box(widget, payload)
                _select(widget)
                widget.focus()
                await pilot.pause()
                await right_click_app_route(app, pilot, widget)
                await pilot.pause()
                await pilot.pause()
                reads.append(other_program_read())
            return reads

    reads = asyncio.run(_drive())
    expected = [f"RC-{k} Ñ€" for k in range(1, 6)] if box_kind == "a" else [f"RL1-{k}\nRL2-{k}" for k in range(1, 6)]
    assert reads == expected, reads


def test_r_paste_24_3_unfocused_multi_line_right_click_copies(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.24/3 (WinCI): an unfocused Box 2 copies the selection it shows."""
    from tests.support.b103_clipboard import _OneBoxApp

    async def _drive() -> tuple:
        app = _OneBoxApp("textarea")
        async with app.run_test(size=(80, 30)) as pilot:
            await pilot.pause()
            widget = app.query_one("#box", TextArea)
            widget.text = "AAAA-BBBB"
            widget.selection = ((0, 0), (0, 4))
            widget.focus()
            await pilot.pause()
            await pilot.click("#other")
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return widget.has_focus

    focused = asyncio.run(_drive())
    assert focused is True
    assert other_program_read() == "AAAA"


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_25_26_win_right_click_copy_app_clipboard(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.25 + .26 (WinCI arm): the app clipboard and the selection."""
    async def _drive() -> tuple:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            app._clipboard = "BEFORE"
            _set_box(widget, "AAAA-BBBB")
            widget.focus()
            await pilot.pause()
            if box_kind == "a":
                widget.selection = (0, 4)
            else:
                widget.selection = ((0, 0), (0, 4))
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return app.clipboard, _box(widget), widget.selection

    clip, value, selection = asyncio.run(_drive())
    assert clip == "AAAA", clip
    assert value == "AAAA-BBBB", value
    assert tuple(selection) == (0, 4) if box_kind == "a" else ((0, 0), (0, 4)), selection


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_27_1_2_right_click_copy_ends_within_typed_key_time(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.27/1-2 (WinCI): median right-click copy end ≤ typed-key time + bound."""
    async def _drive() -> float:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, widget, app)
            samples = []
            for k in range(10):
                _set_box(widget, f"C{k}")
                _select(widget)
                await pilot.pause()
                before = clipboard_sequence_number()
                start = time.monotonic()
                await right_click_app_route(app, pilot, widget)
                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.005)
                    await pilot.pause()
                    if clipboard_sequence_number() != before:
                        break
                samples.append(time.monotonic() - start)
            return key_time, _median(samples)

    key_time, median = asyncio.run(_drive())
    bound = timing_bound(0.1)
    assert median <= key_time + report_margin(f"r_paste_27_{box_kind}", median, key_time + bound), (key_time, median)


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_28_1_2_held_right_click_copy_ends_within_2_5(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.28/1-2 (WinCI): a held right-click copy warns ≤ 2.5 s."""
    _held = _hold_clipboard(8.0)

    async def _drive() -> float:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            notices = install_notice_capture(app)
            _set_box(widget, "AAAA-BBBB")
            if box_kind == "a":
                widget.selection = (0, 4)
            else:
                widget.selection = ((0, 0), (0, 4))
            widget.focus()
            await pilot.pause()
            before = len(notices)
            start = time.monotonic()
            await right_click_app_route(app, pilot, widget)
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                await asyncio.sleep(0.005)
                await pilot.pause()
                if len(notices) > before:
                    return time.monotonic() - start
            return 999.0

    try:
        elapsed = asyncio.run(_drive())
    finally:
        _held["release"].set()
    bound = timing_bound(2.5)
    assert elapsed <= report_margin(f"r_paste_28_{box_kind}", elapsed, bound), elapsed


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_29_30_win_right_click_paste_placement(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.29/1 + .30/1 (WinCI arm): a right-click pastes at the cursor."""
    other_program_write("P1 line\nsecond")
    from tests.support.b103_clipboard import _OneBoxApp

    async def _drive() -> str:
        app = _OneBoxApp("input" if box_kind == "a" else "textarea")
        async with app.run_test(size=(80, 30)) as pilot:
            await pilot.pause()
            widget = app.query_one("#box")
            if box_kind == "a":
                widget.value = "ab"
            else:
                widget.text = "ab"
            widget.focus()
            await pilot.pause()
            if box_kind == "a":
                widget.selection = (1, 1)
            else:
                widget.selection = ((0, 1), (0, 1))
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return _box(widget)

    value = asyncio.run(_drive())
    assert value == ("aP1 lineb" if box_kind == "a" else "aP1 line\nsecondb"), value


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_31_1_2_right_click_paste_ends_within_typed_key_time(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.31/1-2 (WinCI): median right-click paste end ≤ typed-key time + bound."""
    other_program_write(P1000)

    async def _drive() -> float:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            key_time = await typed_key_time(pilot, widget, app)
            samples = []
            for _ in range(10):
                _set_box(widget, "")
                await pilot.pause()
                start = time.monotonic()
                await right_click_app_route(app, pilot, widget)
                samples.append(await _wait_for_box(pilot, widget, P1000))
            return key_time, _median(samples)

    key_time, median = asyncio.run(_drive())
    bound = timing_bound(0.1)
    assert median <= key_time + report_margin(f"r_paste_31_{box_kind}", median, key_time + bound), (key_time, median)


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_31_5_6_right_click_no_text_no_powershell(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.31/5-6 (WinCI): a non-text clipboard right-click → 0 starts."""
    from s19_app.tui import os_clipboard_input as mod

    for arm in ("file-drop", "bitmap"):
        _write_nontext_clipboard(arm)
        started = install_process_spy(mod)

        async def _drive() -> str:
            app = S19TuiApp(base_dir=tmp_path)
            app._clipboard = "APP-TEXT"
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
                    widget.text = ""
                widget.focus()
                await pilot.pause()
                await right_click_app_route(app, pilot, widget)
                await pilot.pause(0.2)
                return _box(widget)

        value = asyncio.run(_drive())
        assert value == "APP-TEXT", value
        assert started == [], started


@pytest.mark.serial_timing
@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_32_1_2_held_right_click_paste_ends_within_2_5(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-PASTE.32/1-2 (WinCI): a held right-click paste ends ≤ 2.5 s."""
    _held = _hold_clipboard(8.0)

    async def _drive() -> float:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
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
            start = time.monotonic()
            await right_click_app_route(app, pilot, widget)
            elapsed = await _wait_for_box(pilot, widget, "APP-TEXT")
            return elapsed

    try:
        elapsed = asyncio.run(_drive())
    finally:
        _held["release"].set()
    bound = timing_bound(2.5)
    assert elapsed <= report_margin(f"r_paste_32_{box_kind}", elapsed, bound), elapsed


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_6_5_win_right_click_pastes_app_clipboard(
    tmp_path: Path, os_clipboard_ready, box_kind: str
) -> None:
    """R-TUI-043.6/5 (WinCI arm): a right-click pastes the app clipboard."""
    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "APP-TEXT"
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
                widget.text = ""
            widget.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause(0.2)
            return _box(widget)

    assert asyncio.run(_drive()) == "APP-TEXT"


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_043_11_2_right_click_keeps_code_page(tmp_path: Path, os_clipboard_ready, box_kind: str) -> None:
    """R-TUI-043.11/2 (WinCI): a right-click paste keeps P1's code points."""
    other_program_write(P1)

    async def _drive() -> str:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return _box(widget)

    assert asyncio.run(_drive()) == P1


def test_r_tui_043_12_3_win_right_click_held_logs_warning(tmp_path: Path, os_clipboard_ready) -> None:
    """R-TUI-043.12/3 (WinCI arm): a held right-click read logs ≥ 1 WARNING."""
    from tests.support.b103_clipboard import install_log_capture, remove_log_capture

    _held = _hold_clipboard(8.0)

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
            deadline = time.monotonic() + 5.0
            n = 0
            while time.monotonic() < deadline:
                n = sum(1 for r in records if r[0] == "s19_app.tui.os_clipboard_input" and r[1] == "WARNING")
                if n >= 1:
                    break
                await asyncio.sleep(0.005)
                await pilot.pause()
            remove_log_capture(records)
            return n

    try:
        n = asyncio.run(_drive())
    finally:
        _held["release"].set()
    assert n >= 1


def test_r_tui_043_13_2_win_right_click_no_log_leak(tmp_path: Path, os_clipboard_ready) -> None:
    """R-TUI-043.13/2 (WinCI arm): a right-click paste/copy leak nothing to the log."""
    from tests.support.b103_clipboard import install_log_capture, remove_log_capture

    other_program_write("SECRET-TEXT-45")

    async def _drive() -> list:
        app = S19TuiApp(base_dir=tmp_path)
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


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_tui_044_2_6_win_right_click_paste_capped(tmp_path: Path, os_clipboard_ready, box_kind: str) -> None:
    """R-TUI-044.2/6 (WinCI arm): a right-click paste of P70k → 65,536."""
    other_program_write(P70K)

    async def _drive() -> int:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            widget.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            return len(_box(widget))

    assert asyncio.run(_drive()) == CAP


@pytest.mark.parametrize("box_kind", ["a", "m"], ids=["single", "multi"])
def test_r_paste_12_3_win_right_click_copy_over_limit(tmp_path: Path, os_clipboard_ready, box_kind: str) -> None:
    """R-PASTE.12/3 (WinCI arm): a right-click copy of P70k → 65,536 on the OS."""
    async def _drive() -> None:
        async for app, pilot, widget in (_box_a(tmp_path) if box_kind == "a" else _box_m(tmp_path)):
            _set_box(widget, P70K)
            _select(widget)
            widget.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            await pilot.pause()

    asyncio.run(_drive())
    assert len(other_program_read()) == CAP


def test_r_paste_10_2_win_right_click_copy_logs_warning(tmp_path: Path, os_clipboard_ready) -> None:
    """R-PASTE.10/2 (WinCI arm): a failed right-click copy logs ≥ 1 WARNING."""
    from tests.support.b103_clipboard import install_log_capture, remove_log_capture

    _held = _hold_clipboard(8.0)

    async def _drive() -> int:
        async for app, pilot, widget in _box_a(tmp_path):
            records = install_log_capture()
            widget.value = "SECRET-RC-44"
            widget.selection = (0, len(widget.value))
            widget.focus()
            await pilot.pause()
            await right_click_app_route(app, pilot, widget)
            await pilot.pause()
            await pilot.pause()
            n = sum(1 for r in records if r[1] == "WARNING")
            remove_log_capture(records)
            return n

    try:
        n = asyncio.run(_drive())
    finally:
        _held["release"].set()
    assert n >= 1


# ---------------------------------------------------------------------------
# PowerShell by its system path (WinCI)
# ---------------------------------------------------------------------------


def test_r_paste_16_1_read_rescue_starts_system_powershell(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.16/1 (WinCI): the read rescue starts the system PowerShell path."""
    from s19_app.tui import os_clipboard_input as mod

    other_program_write("PS-READ")
    started = install_process_spy(mod)
    original = mod._STRATEGIES
    mod._STRATEGIES = (("ctypes-win32", lambda: None),) + original[1:]
    try:
        async def _drive() -> str:
            async for app, pilot, widget in _box_a(tmp_path):
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+v")
                await pilot.pause()
                return widget.value

        value = asyncio.run(_drive())
    finally:
        mod._STRATEGIES = original
    assert value == "PS-READ", value
    assert started and started[0].lower() == mod._system_powershell().lower(), started


def test_r_paste_16_2_write_rescue_starts_system_powershell(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.16/2 (WinCI): the write rescue starts the system PowerShell path."""
    from s19_app.tui import os_clipboard_input as mod

    started = install_process_spy(mod)

    async def _drive() -> None:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.value = "PS-WRITE"
            widget.selection = (0, len(widget.value))
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+c")
            await pilot.pause()
            await pilot.pause()

    asyncio.run(_drive())
    assert other_program_read() == "PS-WRITE"
    assert started and started[0].lower() == mod._system_powershell().lower(), started


def test_r_paste_16_3_decoy_powershell_never_runs(tmp_path: Path, os_clipboard_ready) -> None:
    """R-PASTE.16/3 (WinCI): a decoy ``powershell.exe`` in cwd/PATH never runs."""
    from s19_app.tui import os_clipboard_input as mod

    other_program_write("PS-READ")
    started = install_process_spy(mod)

    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            return widget.value

    value = asyncio.run(_drive())
    assert value == "PS-READ", value
    assert not any("decoy" in str(p).lower() for p in started), started


@pytest.mark.parametrize("mode", ["read", "write"], ids=["read", "write"])
def test_r_paste_17_no_powershell_starts_nothing(
    tmp_path: Path, os_clipboard_ready, mode: str
) -> None:
    """R-PASTE.17/1-2 (WinCI): a missing system PowerShell starts nothing."""
    from s19_app.tui import os_clipboard_input as mod
    from tests.support.b103_clipboard import _own_write

    started = install_process_spy(mod)

    async def _drive() -> str:
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
            if mode == "read":
                _own_write("")
                await pilot.press("ctrl+v")
            else:
                box.value = "PS-WRITE"
                box.selection = (0, len(box.value))
                await pilot.pause()
                await pilot.press("ctrl+c")
            await pilot.pause()
            return box.value

    value = asyncio.run(_drive())
    assert started == [], started
    if mode == "read":
        assert value == "APP-TEXT", value


# ---------------------------------------------------------------------------
# R-PASTE.21/5 — a direct Win32 call on a non-isolated host (WinCI pytester)
# ---------------------------------------------------------------------------


def test_r_paste_21_5_direct_win32_call_opens_nothing_and_fails(pytester) -> None:
    """R-PASTE.21/5 (WinCI pytester): direct ``_write_via_ctypes`` / ``_read_via_ctypes``
    fail without opening the clipboard on a non-isolated host."""
    from pathlib import Path as _P

    repo = _P(__file__).resolve().parents[1]
    pytester.makeconftest(
        "import os\n"
        "os.environ['GITHUB_ACTIONS'] = 'false'\n"
        "os.environ.pop('RUNNER_ENVIRONMENT', None)\n"
        "pytest_plugins = ['tests.conftest']\n"
    )
    (pytester.path / "test_direct.py").write_text(
        "import sys\n"
        "def test_write():\n"
        "    from s19_app.tui import os_clipboard_input as m\n"
        "    assert m._write_via_ctypes('x') is False\n"
        "def test_read():\n"
        "    from s19_app.tui import os_clipboard_input as m\n"
        "    assert m._read_via_ctypes() is None\n",
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
    result.assert_outcomes(failed=2)
    assert "OS clipboard not isolated:" in result.stdout.str()
