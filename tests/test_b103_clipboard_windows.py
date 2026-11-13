"""Batch-103 Inc 1a clipboard Windows — the WinCI cases (G-T2).

Summary:
    The OS-clipboard arms that run only on the hosted Windows runner
    (``.github/workflows/clipboard-windows.yml``). Every test requests the
    ``os_clipboard_ready`` fixture: off Windows it is skipped with the reason
    ``Windows only``; on a non-isolated Windows host it fails before any open
    (R-PASTE.21); on a hosted runner whose probe failed it is skipped as
    ``runner clipboard unusable`` (R-PASTE.22). The probe test itself
    (``test_runner_clipboard_probe``) FAILS on a failed probe
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
import logging
import os
import queue
import shutil
import subprocess
import sys
import textwrap
import threading
import time
import xml.sax.saxutils
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


def _content_shape(value: object) -> str:
    if value is None:
        return "none"
    if isinstance(value, str):
        return f"chars={len(value)}, line_breaks={value.count(chr(10))}"
    if isinstance(value, (list, tuple)):
        lengths = [len(item) if isinstance(item, str) else None for item in value]
        return f"items={len(value)}, string_item_chars={lengths}"
    return f"type={type(value).__name__}"


def _assert_content_equal(actual: object, expected: object, label: str) -> None:
    if actual != expected:
        raise AssertionError(
            f"{label}: content mismatch; "
            f"expected {_content_shape(expected)}, actual {_content_shape(actual)}"
        )


def _disclosure_forms(payload: str) -> dict[str, str]:
    escaped = payload.encode("unicode_escape").decode("ascii")
    xml_text = xml.sax.saxutils.escape(payload)
    xml_numeric = xml_text.replace("\r", "&#13;")
    xml_attribute = xml.sax.saxutils.escape(
        payload, {'"': "&quot;", "'": "&apos;"}
    ).replace("\r", "&#13;").replace("\n", "&#10;").replace("\t", "&#09;")
    return {
        "full": payload,
        "prefix": payload[:16],
        "repr": repr(payload),
        "escape": escaped,
        "escape-prefix": escaped[:16],
        "xml": xml_text,
        "xml-prefix": xml_text[:16],
        "xml-numeric": xml_numeric,
        "xml-numeric-prefix": xml_numeric[:16],
        "xml-attribute": xml_attribute,
        "xml-attribute-prefix": xml_attribute[:16],
    }


def _formatted_log_entry(entry: object) -> str:
    if isinstance(entry, logging.LogRecord):
        return logging.Formatter().format(entry)
    if isinstance(entry, (list, tuple)) and len(entry) >= 3:
        return _formatted_log_entry(entry[2])
    return str(entry)


def _assert_log_excludes(messages: list, payload: str, label: str) -> None:
    forms = _disclosure_forms(payload)
    matches = []
    for index, entry in enumerate(messages):
        formatted = _formatted_log_entry(entry)
        names = [name for name, needle in forms.items() if needle and needle in formatted]
        if names:
            matches.append((index, names))
    assert not matches, (
        f"{label}: clipboard-derived content in {len(matches)} of {len(messages)} "
        f"captured records at indexes {[index for index, _ in matches]}; "
        f"forms={sorted({name for _, names in matches for name in names})}"
    )


def _probe_failure_metadata(result: object) -> str:
    detail = str(result)
    structured_stage = getattr(result, "stage", None)
    if isinstance(structured_stage, str) and structured_stage:
        stage = structured_stage
    elif detail == "win32 write failed":
        stage = "win32-write"
    elif detail.startswith("PowerShell read raised "):
        stage = "powershell-read-exception"
    elif detail.startswith(
        (
            "win32 write ok, PowerShell read mismatch;",
            "win32 write ok; PowerShell read mismatch;",
        )
    ):
        stage = "round-trip-mismatch"
    else:
        stage = "unclassified"
    return f"stage={stage}, result_chars={len(detail)}"


async def _wait_for_box(pilot, widget: object, expected: str, timeout: float = 10.0) -> float:
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if expected[:10] in _box(widget):
            return time.monotonic() - start
        await asyncio.sleep(0.005)
        await pilot.pause()
    actual = _box(widget)
    raise AssertionError(
        f"box did not reach expected content within {timeout:.1f}s; "
        f"expected {_content_shape(expected)}, actual {_content_shape(actual)}"
    )


# ---------------------------------------------------------------------------
# The probe test (R-PASTE.23/2, R-PASTE.22/2)
# ---------------------------------------------------------------------------


def test_runner_clipboard_probe() -> None:
    """R-PASTE.23/2 + R-PASTE.22/2: the hosted runner's clipboard probe.

    Fails (never skips) with ``runner clipboard unusable`` plus redacted
    stage/length metadata when the probe cannot round-trip its nonce, so a
    green job can never mean "all OS clipboard tests skipped" (D-7 B)."""
    from tests.support.b103_clipboard import clipboard_probe, require_isolated_clipboard

    require_isolated_clipboard("windows")
    usable, result = clipboard_probe()
    if not usable:
        pytest.fail(f"runner clipboard unusable: {_probe_failure_metadata(result)}")


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
    from tests.support.b103_clipboard import require_isolated_clipboard

    require_isolated_clipboard("windows")
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
        _release_clipboard(_held)
    bound = timing_bound(2.5)
    assert elapsed <= report_margin(f"r_tui_043_10_2_{box_kind}", elapsed, bound), elapsed


def _reap_holder(proc) -> None:
    """Attempt every bounded cleanup stage and reject a surviving holder."""
    errors: list[tuple[str, BaseException]] = []

    def _attempt(stage: str, action) -> None:
        try:
            action()
        except BaseException as exc:
            errors.append((stage, exc))

    def _kill_if_running() -> None:
        if proc.poll() is None:
            proc.kill()

    def _close_stdout() -> None:
        if proc.stdout is not None:
            proc.stdout.close()

    def _check_death() -> None:
        if proc.poll() is None:
            raise RuntimeError("clipboard holder process is still running after cleanup")

    for stage, action in (
        ("initial kill", _kill_if_running),
        ("bounded reap", lambda: proc.wait(timeout=3.0)),
        ("final kill", _kill_if_running),
        ("final reap", lambda: proc.wait(timeout=1.0)),
        ("stdout close", _close_stdout),
        ("death check", _check_death),
    ):
        _attempt(stage, action)
    if errors:
        primary = errors[0][1]
        for stage, error in errors[1:]:
            primary.add_note(f"clipboard holder cleanup {stage}: {type(error).__name__}")
        raise primary


def _release_clipboard(state: dict) -> None:
    """Release and reap independently, preserving the first observed error."""
    errors: list[tuple[str, BaseException]] = []

    def _capture_supervisor_error() -> None:
        error = state.get("error")
        if error is not None and all(error is not prior for _, prior in errors):
            errors.append(("supervisor", error))

    def _attempt(stage: str, action) -> None:
        try:
            action()
        except BaseException as exc:
            errors.append((stage, exc))
        finally:
            _capture_supervisor_error()

    def _check_supervisor() -> None:
        if state["supervisor"].is_alive():
            raise AssertionError("clipboard holder supervisor did not finish")

    def _check_holder() -> None:
        if state["proc"].poll() is None:
            raise RuntimeError("clipboard holder process is still running after release")

    _capture_supervisor_error()
    for stage, action in (
        ("release signal", state["release"].set),
        ("supervisor join", lambda: state["supervisor"].join(timeout=5.0)),
        ("holder cleanup", lambda: _reap_holder(state["proc"])),
        ("supervisor final join", lambda: state["supervisor"].join(timeout=1.0)),
        ("supervisor death check", _check_supervisor),
        ("holder death check", _check_holder),
    ):
        _attempt(stage, action)
    if errors:
        primary = errors[0][1]
        for stage, error in errors[1:]:
            primary.add_note(f"clipboard holder release {stage}: {type(error).__name__}")
        raise primary


def _hold_clipboard(seconds: float) -> dict:
    """Hold the clipboard in a separate, bounded-lifetime process.

    Readiness uses binary stdout and bounded queue/thread operations. Every
    acquisition failure after ``Popen`` attempts final kill/wait, stream close,
    reader/supervisor joins and death checks. Caller release performs each
    action independently and never accepts a live holder or supervisor as a
    successful cleanup; later failures become notes on the first error.
    """
    from tests.support.b103_clipboard import require_isolated_clipboard

    require_isolated_clipboard("windows")
    script = textwrap.dedent(
        """
        import ctypes
        import sys
        from ctypes import wintypes

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID,
        ]
        user32.CreateWindowExW.restype = wintypes.HWND
        kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetModuleHandleW.restype = wintypes.HMODULE
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL
        user32.DestroyWindow.argtypes = [wintypes.HWND]
        user32.DestroyWindow.restype = wintypes.BOOL
        kernel32.Sleep.argtypes = [wintypes.DWORD]
        kernel32.Sleep.restype = None

        hwnd = user32.CreateWindowExW(
            0, "STATIC", "b103-holder", 0, 0, 0, 0, 0,
            -3, None, kernel32.GetModuleHandleW(None), None,
        )
        if not hwnd:
            print("WINDOW-FAILED", flush=True)
            sys.exit(1)
        opened = False
        try:
            if not user32.OpenClipboard(hwnd):
                print("OPEN-FAILED", flush=True)
                sys.exit(1)
            opened = True
            print("HOLDING", flush=True)
            while True:
                kernel32.Sleep(20)
        finally:
            if opened:
                user32.CloseClipboard()
            user32.DestroyWindow(hwnd)
        """
    )
    reader = None
    supervisor = None
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        ready_lines = queue.Queue(maxsize=1)

        def _read_ready() -> None:
            try:
                ready_lines.put(proc.stdout.readline())
            except Exception as exc:
                ready_lines.put(exc)

        reader = threading.Thread(target=_read_ready, daemon=True)
        reader.start()
        try:
            ready = ready_lines.get(timeout=5.0)
        except queue.Empty as exc:
            raise RuntimeError("clipboard holder readiness timed out") from exc
        reader.join(timeout=1.0)
        if reader.is_alive():
            raise RuntimeError("clipboard holder readiness reader did not finish")
        if isinstance(ready, Exception):
            raise RuntimeError("clipboard holder readiness read failed") from ready
        if ready.strip() != b"HOLDING":
            raise RuntimeError(
                "clipboard holder failed readiness: "
                f"output_bytes={len(ready)}, exited={proc.poll() is not None}"
            )
        if proc.poll() is not None:
            raise RuntimeError(f"clipboard holder exited after HOLDING: {proc.returncode}")
        if _open_clipboard_probe() != 0:
            raise RuntimeError(
                "clipboard hold not effective: parent OpenClipboard returned "
                "nonzero (expected 0) while the child reports HOLDING"
            )
        if proc.poll() is not None:
            raise RuntimeError("clipboard holder did not stay alive")

        state = {"proc": proc, "release": threading.Event()}

        def _supervisor() -> None:
            try:
                state["release"].wait(timeout=seconds)
            except BaseException as exc:
                state["error"] = exc
            finally:
                try:
                    _reap_holder(proc)
                except BaseException as exc:
                    if state.get("error") is None:
                        state["error"] = exc
                    else:
                        state["error"].add_note(
                            f"clipboard holder supervisor reap: {type(exc).__name__}"
                        )

        supervisor = threading.Thread(target=_supervisor, daemon=True)
        state["supervisor"] = supervisor
        supervisor.start()
        return state
    except BaseException as primary:
        def _cleanup(stage: str, action) -> None:
            try:
                action()
            except BaseException as cleanup_error:
                primary.add_note(
                    f"clipboard holder error cleanup {stage}: "
                    f"{type(cleanup_error).__name__}"
                )

        def _check_reader() -> None:
            if reader.is_alive():
                raise RuntimeError("clipboard holder readiness reader is still alive")

        def _check_supervisor() -> None:
            if supervisor.is_alive():
                raise RuntimeError("clipboard holder supervisor is still alive")

        _cleanup("process", lambda: _reap_holder(proc))
        if reader is not None:
            _cleanup("reader join", lambda: reader.join(timeout=1.0))
            _cleanup("reader death check", _check_reader)
        if supervisor is not None:
            _cleanup("supervisor join", lambda: supervisor.join(timeout=1.0))
            _cleanup("supervisor death check", _check_supervisor)
        raise


def _open_clipboard_probe() -> int:
    """This process's ``OpenClipboard(None)`` BOOL (0 = held by another task).

    Used by :func:`_hold_clipboard` to verify the child really holds the
    clipboard: a nonzero return (this process could open it) closes the
    clipboard again and signals the hold is ineffective.
    """
    from tests.support.b103_clipboard import require_isolated_clipboard

    require_isolated_clipboard("windows")
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


def _exercise_holder_failure_controls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise SEC-01 holder failures with inert binary process doubles."""
    real_thread = threading.Thread

    class _Stream:
        def __init__(self, ready: bytes = b"") -> None:
            self.ready = ready
            self.closed = False
            self.close_calls = 0

        def readline(self) -> bytes:
            return self.ready

        def close(self) -> None:
            self.closed = True
            self.close_calls += 1

    class _Process:
        def __init__(
            self,
            ready: bytes = b"",
            *,
            returncode: int | None = None,
            kill_errors=(),
            wait_errors=(),
            unkillable: bool = False,
        ) -> None:
            self.stdout = _Stream(ready)
            self.returncode = returncode
            self.kill_errors = list(kill_errors)
            self.wait_errors = list(wait_errors)
            self.unkillable = unkillable
            self.kill_requested = False
            self.kill_calls = 0
            self.waits = []
            self.poll_calls = 0
            self.died_after_kill_call = None

        def poll(self) -> int | None:
            self.poll_calls += 1
            return self.returncode

        def kill(self) -> None:
            self.kill_calls += 1
            error = self.kill_errors.pop(0) if self.kill_errors else None
            if error is not None:
                raise error
            if not self.unkillable:
                self.kill_requested = True

        def wait(self, *, timeout: float) -> int | None:
            self.waits.append(timeout)
            error = self.wait_errors.pop(0) if self.wait_errors else None
            if error is not None:
                raise error
            if self.returncode is None and self.kill_requested:
                self.returncode = 0
                self.died_after_kill_call = self.kill_calls
            if self.returncode is None:
                raise subprocess.TimeoutExpired("holder", timeout)
            return self.returncode

    class _Thread:
        def __init__(
            self,
            *,
            target,
            daemon: bool,
            start_error: BaseException | None = None,
            join_errors=(),
        ) -> None:
            self.target = target
            self.daemon = daemon
            self.start_error = start_error
            self.join_errors = list(join_errors)
            self.alive = False
            self.start_calls = 0
            self.joins = []

        def start(self) -> None:
            self.start_calls += 1
            if self.start_error is not None:
                raise self.start_error
            self.alive = True
            try:
                self.target()
            finally:
                self.alive = False

        def join(self, *, timeout: float) -> None:
            self.joins.append(timeout)
            self.alive = False
            error = self.join_errors.pop(0) if self.join_errors else None
            if error is not None:
                raise error

        def is_alive(self) -> bool:
            return self.alive

    class _Release:
        def __init__(self, error: BaseException | None = None) -> None:
            self.error = error
            self.set_calls = 0

        def set(self) -> None:
            self.set_calls += 1
            if self.error is not None:
                raise self.error

    class _Supervisor:
        def __init__(
            self, alive: bool, join_error: BaseException | None = None
        ) -> None:
            self.alive = alive
            self.join_error = join_error
            self.joins = []

        def join(self, *, timeout: float) -> None:
            self.joins.append(timeout)
            if self.join_error is not None:
                raise self.join_error

        def is_alive(self) -> bool:
            return self.alive

    def _bounded(label: str, control) -> None:
        outcome: list[BaseException] = []

        def run() -> None:
            try:
                control()
            except BaseException as exc:
                outcome.append(exc)

        thread = real_thread(target=run, daemon=True)
        thread.start()
        thread.join(timeout=2.0)
        assert not thread.is_alive(), f"{label}: external deadline expired"
        if outcome:
            raise outcome[0]

    def _install_holder_doubles(
        proc: _Process,
        *,
        readiness_timeout: bool = False,
        reader_start_error: BaseException | None = None,
        reader_join_errors=(),
    ):
        from tests.support import b103_clipboard as support

        class _ReadyQueue:
            def __init__(self) -> None:
                self.value = proc.stdout.ready
                self.timeouts = []

            def put(self, value: object) -> None:
                self.value = value

            def get(self, *, timeout: float) -> object:
                self.timeouts.append(timeout)
                if readiness_timeout:
                    raise queue.Empty
                return self.value

        ready_queue = _ReadyQueue()
        threads = []
        probe_calls = []
        popen_calls = []

        def make_thread(*args, **kwargs):
            if not threads:
                kwargs["start_error"] = reader_start_error
                kwargs["join_errors"] = reader_join_errors
            thread = _Thread(*args, **kwargs)
            threads.append(thread)
            return thread

        def popen(*args, **kwargs):
            popen_calls.append(kwargs)
            return proc

        monkeypatch.setattr(support, "require_isolated_clipboard", lambda *_: None)
        monkeypatch.setattr(subprocess, "Popen", popen)
        monkeypatch.setattr(queue, "Queue", lambda *args, **kwargs: ready_queue)
        monkeypatch.setattr(threading, "Thread", make_thread)
        monkeypatch.setattr(
            sys.modules[__name__],
            "_open_clipboard_probe",
            lambda: probe_calls.append("open") or 0,
        )
        return threads, probe_calls, popen_calls

    def _assert_binary_popen(calls: list) -> None:
        assert len(calls) == 1, "holder did not make exactly one mocked Popen call"
        kwargs = calls[0]
        assert not kwargs.get("text", False), "holder stdout was switched to text mode"
        assert "encoding" not in kwargs and "errors" not in kwargs, (
            "holder binary stdout acquired a text decoder"
        )
        assert kwargs.get("stdout") == subprocess.PIPE
        assert kwargs.get("stderr") == subprocess.STDOUT

    def _assert_reap_attempted(proc: _Process, *, kills: int) -> None:
        assert proc.kill_calls == kills, "holder kill/retry count changed"
        assert proc.waits == [3.0, 1.0], "holder did not attempt both bounded reaps"
        assert proc.stdout.closed and proc.stdout.close_calls == 1, (
            "holder stdout was not closed exactly once"
        )
        assert proc.poll_calls >= 3, "holder death was not checked after cleanup"

    def _assert_cleaned(proc: _Process, *, kills: int) -> None:
        _assert_reap_attempted(proc, kills=kills)
        assert proc.returncode is not None, "holder remained alive after cleanup"

    def _assert_release_cleaned(state: dict, *, kills: int = 1) -> None:
        assert state["release"].set_calls == 1, "release signal was not attempted once"
        assert state["supervisor"].joins == [5.0, 1.0], (
            "release did not attempt both supervisor joins"
        )
        _assert_cleaned(state["proc"], kills=kills)

    def died_after_ready() -> None:
        proc = _Process(b"HOLDING\n", returncode=1)
        threads, probe_calls, popen_calls = _install_holder_doubles(proc)
        try:
            _hold_clipboard(0.1)
        except RuntimeError as exc:
            assert "exited after HOLDING" in str(exc)
        else:
            raise AssertionError("holder accepted a child that died after HOLDING")
        _assert_cleaned(proc, kills=0)
        _assert_binary_popen(popen_calls)
        assert len(threads) == 1 and threads[0].joins == [1.0, 1.0]
        assert not threads[0].is_alive()
        assert probe_calls == []

    def never_ready() -> None:
        proc = _Process()
        join_error = OSError("injected readiness reader join failure")
        threads, probe_calls, popen_calls = _install_holder_doubles(
            proc, readiness_timeout=True, reader_join_errors=[join_error]
        )
        try:
            _hold_clipboard(0.1)
        except RuntimeError as exc:
            assert "readiness timed out" in str(exc)
            assert isinstance(exc.__cause__, queue.Empty)
            assert any("reader join" in note for note in exc.__notes__), (
                "readiness failure masked the reader join failure"
            )
        else:
            raise AssertionError("holder accepted missing readiness")
        _assert_cleaned(proc, kills=1)
        _assert_binary_popen(popen_calls)
        assert len(threads) == 1 and threads[0].joins == [1.0]
        assert not threads[0].is_alive()
        assert probe_calls == []

    def reader_start_fails() -> None:
        proc = _Process()
        start_error = OSError("injected readiness reader start failure")
        threads, probe_calls, popen_calls = _install_holder_doubles(
            proc, reader_start_error=start_error
        )
        try:
            _hold_clipboard(0.1)
        except OSError as exc:
            assert exc is start_error, "reader start failure was masked by cleanup"
        else:
            raise AssertionError("holder ignored a readiness reader start failure")
        _assert_cleaned(proc, kills=1)
        _assert_binary_popen(popen_calls)
        assert len(threads) == 1 and threads[0].start_calls == 1
        assert threads[0].joins == [1.0] and not threads[0].is_alive()
        assert probe_calls == []

    def kill_and_wait_failures() -> None:
        kill_error = OSError("injected kill failure")
        killed = _Process(kill_errors=[kill_error])
        try:
            _reap_holder(killed)
        except OSError as exc:
            assert exc is kill_error, "kill failure was masked by later cleanup"
        else:
            raise AssertionError("holder ignored an injected kill failure")
        _assert_cleaned(killed, kills=2)
        assert killed.died_after_kill_call == 2, "kill retry did not reap the holder"

        timeout = subprocess.TimeoutExpired("holder", 3.0)
        waiting = _Process(wait_errors=[timeout])
        try:
            _reap_holder(waiting)
        except subprocess.TimeoutExpired as exc:
            assert exc is timeout, "wait timeout was masked by the final reap"
        else:
            raise AssertionError("holder ignored an injected wait timeout")
        _assert_cleaned(waiting, kills=2)
        assert waiting.died_after_kill_call == 2, (
            "wait timeout did not stay alive until the final kill/wait"
        )

        stuck = _Process(wait_errors=[timeout], unkillable=True)
        try:
            _reap_holder(stuck)
        except subprocess.TimeoutExpired as exc:
            assert exc is timeout, "unkillable holder replaced the primary timeout"
            assert any("death check" in note for note in exc.__notes__), (
                "unkillable holder was not reported by the final death check"
            )
        else:
            raise AssertionError("holder accepted an unkillable process as cleaned")
        _assert_reap_attempted(stuck, kills=2)
        assert stuck.returncode is None and stuck.died_after_kill_call is None

        primary = RuntimeError("injected supervisor failure")
        failing = _Process(wait_errors=[timeout])
        state = {
            "proc": failing,
            "release": _Release(),
            "supervisor": _Supervisor(False),
            "error": primary,
        }
        try:
            _release_clipboard(state)
        except RuntimeError as exc:
            assert exc is primary, "final cleanup masked the supervisor failure"
        else:
            raise AssertionError("release ignored the supervisor failure")
        _assert_release_cleaned(state, kills=2)
        assert failing.died_after_kill_call == 2

    def supervisor_does_not_finish() -> None:
        state = {
            "proc": _Process(),
            "release": _Release(),
            "supervisor": _Supervisor(True),
        }
        try:
            _release_clipboard(state)
        except AssertionError as exc:
            assert "supervisor did not finish" in str(exc)
        else:
            raise AssertionError("release accepted a live supervisor")
        _assert_release_cleaned(state)

    def release_signal_fails() -> None:
        primary = OSError("injected release signal failure")
        state = {
            "proc": _Process(),
            "release": _Release(primary),
            "supervisor": _Supervisor(False),
        }
        try:
            _release_clipboard(state)
        except OSError as exc:
            assert exc is primary, "release signal failure was masked by cleanup"
        else:
            raise AssertionError("release ignored a signal failure")
        _assert_release_cleaned(state)

    def supervisor_join_fails() -> None:
        primary = OSError("injected supervisor join failure")
        state = {
            "proc": _Process(),
            "release": _Release(),
            "supervisor": _Supervisor(False, primary),
        }
        try:
            _release_clipboard(state)
        except OSError as exc:
            assert exc is primary, "supervisor join failure was masked by cleanup"
        else:
            raise AssertionError("release ignored a supervisor join failure")
        _assert_release_cleaned(state)

    controls = (
        ("holder died after readiness", died_after_ready),
        ("holder readiness timeout", never_ready),
        ("holder reader start failure", reader_start_fails),
        ("holder kill/wait failures", kill_and_wait_failures),
        ("holder supervisor timeout", supervisor_does_not_finish),
        ("holder release signal failure", release_signal_fails),
        ("holder supervisor join failure", supervisor_join_fails),
    )
    for label, control in controls:
        monkeypatch.undo()
        _bounded(label, control)


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
        _release_clipboard(_held)
    _assert_content_equal(value, "APP-TEXT", "app clipboard fallback")


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
    _assert_content_equal(value, "APP-TEXT", "app clipboard fallback")
    assert not warnings, f"unexpected clipboard warnings: count={len(warnings)}"
    assert started == [], started


def _write_empty_unicode_text() -> None:
    from tests.support.b103_clipboard import require_isolated_clipboard

    require_isolated_clipboard("windows")
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

    _assert_content_equal(asyncio.run(_drive()), "aP1 lineb", "R-TUI-043.4/1 paste")


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

    _assert_content_equal(asyncio.run(_drive()), "aP1 line\nsecondb", "R-TUI-044.3/1 paste")


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

    _assert_content_equal(asyncio.run(_drive()), "ZZ-BBBB", "R-TUI-043.5/1-2 selection")


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

    _assert_content_equal(asyncio.run(_drive()), P1, "R-TUI-043.11/1 code page")


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
        _release_clipboard(_held)
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
            return records

    messages = asyncio.run(_drive())
    _assert_log_excludes(messages, "SECRET-TEXT-42", "R-TUI-043.13/1 paste")
    _assert_log_excludes(messages, "SECRET-COPY-43", "R-TUI-043.13/1 copy")


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
    from tests.support.b103_clipboard import require_isolated_clipboard

    require_isolated_clipboard("windows")
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
    _assert_content_equal(first, "A[13DBC", "single-line unsafe paste first")
    _assert_content_equal(second, "L1[2J", "single-line unsafe paste second")


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
    _assert_content_equal(first, "A[13DBC", "single-line unsafe paste first")
    _assert_content_equal(second, "L1[2J", "single-line unsafe paste second")


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
    _assert_content_equal(first, ["A[13DBC\tD", "E"], "multi-line unsafe paste first")
    _assert_content_equal(second, ["L1 Ñ€[2J", "L2 漢"], "multi-line unsafe paste second")


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

    _assert_content_equal(
        asyncio.run(_drive()), ["A[13DBC\tD", "E"], "R-PASTE.35/4 right-click paste"
    )


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
    _assert_content_equal(reads, expected, "five consecutive clipboard copies")


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

    _assert_content_equal(asyncio.run(_drive()), "COPYME-1", "R-PASTE.3 app clipboard")


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
    _assert_content_equal(internal, "BEFORE", "R-PASTE.5 app clipboard")
    _assert_content_equal(other_program_read(), "OS-BEFORE", "R-PASTE.5 OS clipboard")


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
    _assert_content_equal(internal, "CUTME-1", "R-PASTE.6 app clipboard")
    _assert_content_equal(other_program_read(), "CUTME-1", "R-PASTE.6 OS clipboard")


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
        _release_clipboard(_held)
    assert warnings, "held clipboard write produced no warning"
    _assert_content_equal(warnings[-1][1], WRITE_FAIL_WARNING, "R-PASTE.9/2 warning")


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
        _release_clipboard(_held)
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
        _release_clipboard(_held)
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
        _release_clipboard(_held)
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
        _release_clipboard(_held)
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
        _release_clipboard(_held)
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
    _assert_content_equal(reads, expected, "five consecutive clipboard copies")


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
    _assert_content_equal(other_program_read(), "AAAA", "R-PASTE.24/3 OS clipboard")


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
    _assert_content_equal(clip, "AAAA", "R-PASTE.25/.26 app clipboard")
    _assert_content_equal(value, "AAAA-BBBB", "R-PASTE.25/.26 source selection")
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
        _release_clipboard(_held)
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
    expected = "aP1 lineb" if box_kind == "a" else "aP1 line\nsecondb"
    _assert_content_equal(value, expected, "R-PASTE.29/.30 right-click paste")


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
        _assert_content_equal(value, "APP-TEXT", "app clipboard fallback")
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
        _release_clipboard(_held)
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

    _assert_content_equal(asyncio.run(_drive()), "APP-TEXT", "R-TUI-043.6/5 right-click fallback")


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

    _assert_content_equal(asyncio.run(_drive()), P1, "R-TUI-043.11/2 code page")


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
        _release_clipboard(_held)
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
            return records

    messages = asyncio.run(_drive())
    _assert_log_excludes(messages, "SECRET-TEXT-45", "R-TUI-043.13/2 paste")
    _assert_log_excludes(messages, "SECRET-COPY-46", "R-TUI-043.13/2 copy")


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
        _release_clipboard(_held)
    assert n >= 1


# ---------------------------------------------------------------------------
# PowerShell by its system path (WinCI)
# ---------------------------------------------------------------------------


def test_r_paste_16_1_read_rescue_starts_system_powershell(
    tmp_path: Path, os_clipboard_ready
) -> None:
    """R-PASTE.16/1: exact binary reader; single-line UI keeps only line one."""
    from s19_app.tui import os_clipboard_input as mod

    first_line = "PS-READ-Ñ"
    expected = first_line + "\rL2\r\nL3\n"
    other_program_write(expected)
    started = install_process_spy(mod)
    original = mod._STRATEGIES
    mod._STRATEGIES = (("ctypes-win32", lambda: None),) + original[1:]
    try:
        reader_value = mod.read_os_clipboard()

        async def _drive() -> str:
            async for app, pilot, widget in _box_a(tmp_path):
                widget.focus()
                await pilot.pause()
                await pilot.press("ctrl+v")
                await _wait_for_box(pilot, widget, first_line)
                return widget.value

        value = asyncio.run(_drive())
    finally:
        mod._STRATEGIES = original
    _assert_content_equal(reader_value, expected, "R-PASTE.16/1 exact reader")
    _assert_content_equal(value, first_line, "R-PASTE.16/1 single-line paste")
    system_ps = mod._system_powershell()
    assert system_ps and len(started) == 2 and all(
        isinstance(program, str)
        and os.path.normcase(program) == os.path.normcase(system_ps)
        for program in started
    ), f"R-PASTE.16/1 expected two system PowerShell starts; starts={len(started)}"


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
    _assert_content_equal(other_program_read(), "PS-WRITE", "R-PASTE.16/2 write rescue")
    system_ps = mod._system_powershell()
    assert system_ps and started and started[0].lower() == system_ps.lower(), (
        f"R-PASTE.16/2 expected a system PowerShell start; starts={len(started)}"
    )


def test_r_paste_16_3_decoy_powershell_never_runs(
    tmp_path: Path, os_clipboard_ready, monkeypatch
) -> None:
    """R-PASTE.16/3: forced read/write rescues ignore real cwd/PATH decoys."""
    from s19_app.tui import os_clipboard_input as mod

    other_program_write("PS-READ")
    system_ps = mod._system_powershell()
    system_dir = mod._system_directory()
    assert system_ps and system_dir, "system PowerShell is required for the decoy control"

    decoy_cwd = tmp_path / "decoy-cwd"
    decoy_path = tmp_path / "decoy-path"
    decoy_cwd.mkdir()
    decoy_path.mkdir()
    decoy_source = tmp_path / "decoy.cs"
    decoy_source.write_text(
        "using System; using System.IO; internal static class Decoy { "
        "private static int Main() { "
        "var marker = Environment.GetEnvironmentVariable(\"B103_DECOY_MARKER\"); "
        "if (!String.IsNullOrEmpty(marker)) File.WriteAllText(marker, \"executed\"); "
        "return 0; } }",
        encoding="utf-8",
    )
    windows_dir = Path(system_dir).parent
    compiler = next(
        (
            candidate
            for candidate in (
                windows_dir / "Microsoft.NET" / "Framework64" / "v4.0.30319" / "csc.exe",
                windows_dir / "Microsoft.NET" / "Framework" / "v4.0.30319" / "csc.exe",
            )
            if candidate.is_file()
        ),
        None,
    )
    assert compiler is not None, "absolute .NET Framework compiler not found for decoy"
    decoy_in_path = decoy_path / "powershell.exe"
    compiled = subprocess.run(
        [str(compiler), "/nologo", "/target:exe", f"/out:{decoy_in_path}", str(decoy_source)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30.0,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert compiled.returncode == 0, (
        "decoy compilation failed: "
        f"exit={compiled.returncode}, stdout_chars={len(compiled.stdout)}, "
        f"stderr_chars={len(compiled.stderr)}"
    )
    shutil.copyfile(decoy_in_path, decoy_cwd / "powershell.exe")
    marker = tmp_path / "decoy-executed.marker"
    monkeypatch.setenv("B103_DECOY_MARKER", str(marker))
    monkeypatch.setenv("PATH", str(decoy_path) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.chdir(decoy_cwd)

    original_run = mod.subprocess.run
    original_read = mod._STRATEGIES
    original_write = mod._WRITE_STRATEGIES
    started = install_process_spy(mod)
    mod._STRATEGIES = (
        ("ctypes-win32", lambda: None),
        ("powershell", mod._read_via_powershell),
    )
    mod._WRITE_STRATEGIES = (
        ("win32", lambda _text: False),
        ("powershell", mod._write_via_powershell),
    )

    async def _drive() -> str:
        async for app, pilot, widget in _box_a(tmp_path):
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await _wait_for_box(pilot, widget, "PS-READ")
            read_value = widget.value
            widget.value = "PS-WRITE"
            widget.selection = (0, len(widget.value))
            await pilot.pause()
            before = clipboard_sequence_number()
            await pilot.press("ctrl+c")
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                await asyncio.sleep(0.005)
                await pilot.pause()
                if clipboard_sequence_number() != before:
                    break
            return read_value

    try:
        read_value = asyncio.run(_drive())
    finally:
        mod._STRATEGIES = original_read
        mod._WRITE_STRATEGIES = original_write
        mod.subprocess.run = original_run
    write_value = other_program_read()

    _assert_content_equal(read_value, "PS-READ", "R-PASTE.16/3 forced read")
    _assert_content_equal(write_value, "PS-WRITE", "R-PASTE.16/3 forced write")
    assert started, "forced PowerShell rescues did not start any process"
    non_system = [
        index
        for index, program in enumerate(started)
        if not isinstance(program, str)
        or os.path.normcase(program) != os.path.normcase(system_ps)
    ]
    assert not non_system, (
        f"non-system PowerShell argv[0] at indexes {non_system}; starts={len(started)}"
    )
    assert not marker.exists(), "decoy PowerShell executed and created its marker"


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
        _assert_content_equal(value, "APP-TEXT", "app clipboard fallback")


# ---------------------------------------------------------------------------
# R-PASTE.21/5 — a direct Win32 call on a non-isolated host (WinCI pytester)
# ---------------------------------------------------------------------------


def test_r_paste_21_5_direct_win32_call_opens_nothing_and_fails(pytester) -> None:
    """R-PASTE.21/5 plus inert binary SEC-01 holder failure controls."""
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
    with pytest.MonkeyPatch.context() as monkeypatch:
        _exercise_holder_failure_controls(monkeypatch)
