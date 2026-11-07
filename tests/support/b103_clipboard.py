"""Batch-103 Inc 1a clipboard test support (G-T; independent tester).

Summary:
    Shared fixtures and helpers for the Inc 1a clipboard tests
    (``tests/test_b103_clipboard_core.py``, ``_windows.py``,
    ``_matrix.py``). One home for the OS-clipboard isolation predicate and
    guard (R-PASTE.21), the hosted-runner clipboard probe (R-PASTE.22,
    .23), the host-platform seam, and the black-box driving helpers of
    ``02-test-cases.md`` §Common fixtures: payloads, the one-box app
    (Box 1 / Box 2), the App-route right-click, the terminal paste, the
    OSC 52 spy, the process spy, notice and log capture, and the timing
    helpers (typed-key time, tick lateness).

    Windows-only helpers (Other-program write/read, Own read/write, the
    held clipboard, the empty Unicode text) are declared here so the
    WinCI arms import them from one place; off Windows they raise a skip
    reason rather than touching a real clipboard. No helper in this module
    opens a clipboard unless ``require_isolated_clipboard`` first passed.

Data Flow:
    - ``clipboard_isolated`` is the pure predicate; ``require_isolated_clipboard``
      wraps it with ``pytest.fail`` so an un-isolated test fails before any open.
    - ``clipboard_probe`` caches its one-shot result per session and is the
      body of the probe test and of the ``os_clipboard_ready`` skip fixture.
    - The driving helpers post real Textual events (keys, ``events.Paste``,
      ``MouseDown``/``MouseUp`` to the App) so the product code under test
      answers, never a stand-in.

Dependencies:
    Uses:
        - ``textual`` (App, events)
        - ``s19_app.tui.os_clipboard_input`` / ``capped_text_area`` (under test)
        - ``tests.support.timing`` (``timing_bound``)
    Used by:
        - ``tests/test_b103_clipboard_core.py``
        - ``tests/test_b103_clipboard_windows.py``
        - ``tests/test_b103_clipboard_matrix.py``
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import subprocess
import sys
import time
from typing import Callable, Optional

import pytest
from textual import events
from textual.app import App, ComposeResult
from textual.widgets import Button, Input, TextArea

from s19_app.tui.capped_text_area import CappedTextArea
from s19_app.tui.os_clipboard_input import OsClipboardInput

# ---------------------------------------------------------------------------
# Host platform seam and the isolation predicate / guard (R-PASTE.21)
# ---------------------------------------------------------------------------

#: Environment override for the host-platform seam. The LinuxH pytester
#: runs (R-PASTE.21/4, R-PASTE.22/1, R-PASTE.23/1-2) set it in their
#: generated conftest so the suite-wide fixture sees ``win32`` at session
#: start without touching ``sys.platform``.
_HOST_PLATFORM_ENV = "B103_HOST_PLATFORM"


def host_platform() -> str:
    """``sys.platform`` by default; overridable through ``B103_HOST_PLATFORM``.

    Summary:
        The one-line seam every isolation consumer reads (``clipboard_isolated``,
        the Windows-file setup skip, ``os_clipboard_ready``) so a LinuxH
        pytester run can pretend to be a Windows host without patching
        ``sys.platform`` in-process.

    Returns:
        str: The host platform name, ``"win32"`` or otherwise.
    """
    return os.environ.get(_HOST_PLATFORM_ENV, sys.platform)


def _logged_account() -> Optional[str]:
    """The logged-on account (``GetUserNameW`` / ``os.getlogin()``), not ``%USERNAME%``."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        size = wintypes.DWORD(256)
        buffer = ctypes.create_unicode_buffer(256)
        ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size))
        return buffer.value
    except Exception:  # pragma: no cover - defensive
        try:
            return os.getlogin()
        except Exception:
            return None


def clipboard_isolated(
    kind: str,
    environ: Optional[dict] = None,
    platform: Optional[str] = None,
    account: Optional[str] = None,
) -> tuple:
    """The pure isolation predicate of R-PASTE.21; never fails a test.

    Summary:
        ``kind="windows"``: isolated iff the platform is ``win32``,
        ``GITHUB_ACTIONS`` = ``true``, ``RUNNER_ENVIRONMENT`` =
        ``github-hosted`` and the logged-on account is ``runneradmin``.
        ``kind="x"``: isolated iff ``DISPLAY`` equals the display the
        session's own Xvfb fixture started (none until it starts). The
        reason names the first term that fails; ``""`` when isolated.

    Args:
        kind (str): ``"windows"`` or ``"x"``.
        environ (Optional[dict]): Environment mapping; defaults to ``os.environ``.
        platform (Optional[str]): Platform name; defaults to :func:`host_platform`.
        account (Optional[str]): Logged-on account; defaults to
            :func:`_logged_account` (Windows only).

    Returns:
        tuple: ``(isolated: bool, reason: str)``.
    """
    env = os.environ if environ is None else environ
    plat = host_platform() if platform is None else platform
    if kind == "windows":
        if plat != "win32":
            return False, f"platform='{plat}'"
        if env.get("GITHUB_ACTIONS", "").lower() != "true":
            return False, "GITHUB_ACTIONS != 'true'"
        if env.get("RUNNER_ENVIRONMENT") != "github-hosted":
            return False, f"RUNNER_ENVIRONMENT='{env.get('RUNNER_ENVIRONMENT')}'"
        acct = _logged_account() if account is None else account
        if acct != "runneradmin":
            return False, f"account='{acct}'"
        return True, ""
    if kind == "x":
        display = env.get("DISPLAY")
        if not display:
            return False, "DISPLAY is not set"
        session_display = env.get("B103_XVFB_DISPLAY")
        if session_display is None or display != session_display:
            return False, "DISPLAY is not the session's private Xvfb display"
        return True, ""
    raise ValueError(f"unknown clipboard isolation kind: {kind!r}")


def require_isolated_clipboard(
    kind: str,
    environ: Optional[dict] = None,
    platform: Optional[str] = None,
    account: Optional[str] = None,
) -> None:
    """Fail the test (never skip) before anything opens a clipboard.

    Summary:
        The isolation guard of this module's helpers: calls
        :func:`clipboard_isolated` and ``pytest.fail``s with
        ``OS clipboard not isolated: <reason>`` when it is not isolated. It
        opens nothing itself; every clipboard helper of this module calls it
        first.

    Args:
        kind (str): ``"windows"`` or ``"x"``.
        environ (Optional[dict]): Passed through to :func:`clipboard_isolated`.
        platform (Optional[str]): Passed through.
        account (Optional[str]): Passed through.
    """
    ok, reason = clipboard_isolated(kind, environ, platform, account)
    if not ok:
        pytest.fail(f"OS clipboard not isolated: {reason}")


# ---------------------------------------------------------------------------
# The hosted-runner clipboard probe (R-PASTE.22, .23)
# ---------------------------------------------------------------------------

#: One-shot body of the probe, replaced by a stand-in in the LinuxH
#: pytester runs (E3A-28). Returns ``(usable: bool, result: str)``.
def _probe_once() -> tuple:
    """Write a nonce with the test's own Win32 code and read it back by a
    separate system PowerShell ``Get-Clipboard -Raw`` process."""
    require_isolated_clipboard("windows")
    nonce = "b103-probe-" + os.urandom(16).hex()
    # Write with the test process's own Win32 code (independent of the
    # product under test), then read back with a separate PowerShell.
    written = _own_write(nonce)
    if not written:
        return False, "win32 write failed"
    try:
        read_back = _other_program_read()
    except Exception as exc:  # pragma: no cover - the layers report themselves
        return False, f"PowerShell read raised {exc!r}"
    if read_back == nonce:
        return True, f"win32 write ok, PowerShell read {nonce!r}"
    return False, f"win32 write ok, PowerShell read {read_back!r}"


_probe_cache: Optional[tuple] = None


def clipboard_probe() -> tuple:
    """The cached clipboard probe; ``(usable, result)``, once per session."""
    global _probe_cache
    if _probe_cache is None:
        _probe_cache = _probe_once()
    return _probe_cache


@pytest.fixture
def os_clipboard_ready() -> None:
    """Skip off Windows; fail (never skip) on a non-isolated Windows host;
    skip with ``runner clipboard unusable: <result>`` on a failed probe."""
    if host_platform() != "win32":
        pytest.skip("Windows only")
    require_isolated_clipboard("windows")
    usable, result = clipboard_probe()
    if not usable:
        pytest.skip(f"runner clipboard unusable: {result}")


# ---------------------------------------------------------------------------
# Contract literals and payloads (02-test-cases.md §Common fixtures)
# ---------------------------------------------------------------------------

READ_FAIL_WARNING = "Clipboard read failed — try Ctrl+Shift+V or type the path manually."
WRITE_FAIL_WARNING = "Clipboard write failed — copied inside the app only."
CAP = 65536

P1 = "COPY-1 Ñoño Ж 漢字 😀"
P2 = "L1 Ñ€\nL2 漢"
P1000 = "0123456789" * 100
P70K = "x" * 70000
P_CTRL = "A\x1b[13DB\x00C\u202e\uD800"
P_CTRL_W = "A\x1b[13DBC"
P_CTRL_L = "L1\x1b[2J\nL2"
P_CTRL_M = "A\x1b[13DB\x00C\tD\r\nE\u202e\uD800"
P_CTRL_MW = "A\x1b[13DBC\tD\r\nE\u202e\uD800"
P2_ESC = "L1 \u00d1\u20ac\x1b[2J\nL2 \u6f22"


# ---------------------------------------------------------------------------
# One-box app (Box 1 / Box 2) and the box accessors
# ---------------------------------------------------------------------------


class _OneBoxApp(App):
    """A Button ``#other`` plus one clipboard box; at least 20 content cells."""

    def __init__(self, box_kind: str) -> None:
        super().__init__()
        self.box_kind = box_kind

    def compose(self) -> ComposeResult:
        yield Button("other", id="other")
        if self.box_kind == "input":
            yield OsClipboardInput("", id="box")
        else:
            yield CappedTextArea("", id="box")


def _box(widget: object) -> str:
    """The editable value of a single- or multi-line box, as the oracle reads it."""
    if isinstance(widget, CappedTextArea):
        return widget.text
    return widget.value


def _set_box(widget: object, text: str) -> None:
    if isinstance(widget, CappedTextArea):
        widget.text = text
    else:
        widget.value = text


def _box_lines(widget: object) -> list:
    """The document lines of a multi-line box (its ``document.lines``)."""
    return list(widget.document.lines) if isinstance(widget, CappedTextArea) else None


async def _select_all(widget: object) -> None:
    if isinstance(widget, CappedTextArea):
        widget.select_all()
    else:
        widget.selection = (0, len(widget.value or ""))


# ---------------------------------------------------------------------------
# Terminal paste and the App-route right-click
# ---------------------------------------------------------------------------


async def terminal_paste(app: App, text: str) -> None:
    """Post ``events.Paste`` to the App, as Textual's driver posts it."""
    app.post_message(events.Paste(text))


async def show_sje_manual(app: App, pilot) -> None:
    """Open Split/Join/Export and switch to the manual-localities tab.

    ``#sje_manual`` starts hidden on the default ranges tab; pressing ``t``
    cycles to the manual tab, which lays the box out and focuses it."""
    app.action_open_split_join_export()
    for _ in range(4):
        await pilot.pause()
    await pilot.press("t")
    for _ in range(4):
        await pilot.pause()


async def show_patch_paste(app: App, pilot) -> None:
    """Show the Patch screen's JSON tab so ``#patch_paste_text`` is laid out.

    ``#patch_paste_text`` lives on the Patch screen's JSON tab and stays
    unmounted (region 0x0) until the ``#patch_tab_json`` chip is pressed;
    key-based paste reaches it through the focus, but a mouse right-click
    needs the box to be visible."""
    app.action_show_screen("patch")
    for _ in range(4):
        await pilot.pause()
    await pilot.click("#patch_tab_json")
    for _ in range(4):
        await pilot.pause()


async def right_click_app_route(app: App, pilot, widget: object) -> None:
    """Deliver the right-click through the App route: a button-3
    ``MouseDown`` then ``MouseUp`` posted to the App back to back (no
    pause), so ``App.on_event`` hit-tests the box and makes the ``Click``
    (E3A-11 d). The post is followed by ``pilot.pause()`` so the App's own
    run loop dispatches the pair — never ``app._process_messages()``, which
    re-composes the screen and raises ``MountError``."""
    region = widget.region
    x = region.x + max(0, min(2, region.width - 1))
    y = region.y
    down = events.MouseDown(widget, x, y, 0, 0, 3, False, False, False, x, y, None)
    up = events.MouseUp(widget, x, y, 0, 0, 3, False, False, False, x, y, None)
    app.post_message(down)
    app.post_message(up)
    await pilot.pause()


async def pilot_right_click(pilot, widget: object, *, offset: tuple = (2, 1)) -> None:
    """``pilot.click(..., button=3)`` — the Pilot route (bypasses ``App.on_event``)."""
    await pilot.click(widget, offset=offset, button=3)


# ---------------------------------------------------------------------------
# OSC 52 spy and the process spy
# ---------------------------------------------------------------------------

_OSC52_RE = re.compile(rb"\x1b\]52;c;([A-Za-z0-9+/=]+)\x07")


def install_osc52_spy(app: App) -> list:
    """Wrap ``app._driver.write``; return the list of decoded OSC 52 payloads.

    Summary:
        A pass-through wrapper that keeps every ``ESC ] 52 ; c ; <b64> BEL``
        sequence and decodes it; every other write is forwarded unchanged.
        The returned list is mutated as the copy tail writes.

    Returns:
        list: Decoded OSC 52 request payloads, in order.
    """
    original = app._driver.write
    decoded: list = []

    def _spy(data) -> None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        for match in _OSC52_RE.findall(data):
            try:
                decoded.append(base64.b64decode(match).decode("utf-8"))
            except Exception:
                decoded.append(match.decode("ascii", "replace"))
        return original(data)

    app._driver.write = _spy  # type: ignore[method-assign]
    return decoded


def install_process_spy(module) -> list:
    """Wrap ``subprocess.run`` on ``module``; return the list of argv[0] paths.

    Summary:
        A pass-through wrapper on process creation that records each program
        path (argv[0]) and then starts it unchanged. The spy belongs on the
        module whose ``subprocess.run`` the product under test uses
        (``s19_app.tui.os_clipboard_input``).

    Returns:
        list: Each started program's argv[0], in order.
    """
    original = module.subprocess.run
    started: list = []

    def _spy(argv, **kwargs):
        started.append(list(argv)[0] if argv else None)
        return original(argv, **kwargs)

    module.subprocess.run = _spy  # type: ignore[assignment]
    return started


# ---------------------------------------------------------------------------
# Notice and log capture
# ---------------------------------------------------------------------------


def install_notice_capture(app: App) -> list:
    """Record ``(severity, message)`` for every ``app.notify`` call."""
    original = app.notify
    records: list = []

    def _spy(message: str, *, severity: str = "information", **kwargs) -> None:
        records.append((severity, str(message)))
        try:
            original(message, severity=severity, **kwargs)
        except Exception:
            pass

    app.notify = _spy  # type: ignore[method-assign]
    return records


class _LogCapture(logging.Handler):
    """A DEBUG handler on the ``s19_app`` logger recording (logger, level, message)."""

    def __init__(self, records: list) -> None:
        super().__init__(level=logging.DEBUG)
        self.records = records

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append((record.name, record.levelname, record.getMessage()))


def install_log_capture() -> list:
    """Attach a DEBUG handler to the ``s19_app`` logger; return the record list."""
    records: list = []
    handler = _LogCapture(records)
    logging.getLogger("s19_app").addHandler(handler)
    return records


def remove_log_capture(records: list) -> None:
    """Remove every handler whose records list is ``records``."""
    logger = logging.getLogger("s19_app")
    for handler in list(logger.handlers):
        if getattr(handler, "records", None) is records:
            logger.removeHandler(handler)


# ---------------------------------------------------------------------------
# Timing helpers (02-test-cases.md §Common fixtures)
# ---------------------------------------------------------------------------


async def typed_key_time(pilot, widget: object, app: App) -> float:
    """Median, over 10 warm presses of ``a``, of press → first 5 ms poll that
    holds ``a`` in the cleared box (2 discarded first)."""
    if isinstance(widget, CappedTextArea):
        widget.text = ""
        widget.focus()
    else:
        widget.value = ""
        widget.focus()
    await pilot.pause()
    samples: list = []
    for _ in range(10):
        _set_box(widget, "")
        await pilot.pause()
        start = time.monotonic()
        await pilot.press("a")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            await asyncio.sleep(0.005)
            await pilot.pause()
            if "a" in _box(widget):
                break
        samples.append(time.monotonic() - start)
    samples = samples[2:]
    samples.sort()
    return samples[len(samples) // 2]


async def _poll_until(pilot, predicate: Callable[[], bool], timeout: float = 10.0) -> float:
    """Poll ``predicate`` every 5 ms until truthy; return elapsed seconds."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if predicate():
            return time.monotonic() - start
        await asyncio.sleep(0.005)
        await pilot.pause()
    raise AssertionError("poll predicate not satisfied within timeout")


async def arm_tick_lateness(app: App, screen, marker: dict, interval: float = 0.05) -> list:
    """Arm a 50 ms interval timer on ``screen``; record lateness per tick.

    Summary:
        ``marker`` is a dict the pass-through read/write entry flips to
        ``True`` once the clipboard layer started; a vacuous run (the
        marker never set before the end) fails in the test. Returns the
        list of lateness values (actual − due)."""
    lateness: list = []
    due = time.monotonic() + interval

    def _tick():
        nonlocal due
        now = time.monotonic()
        lateness.append(now - due)
        due = now + interval

    # Re-arm a repeating timer via the screen's ``set_interval``.
    timer = screen.set_interval(interval, _tick)
    try:
        yield lateness
    finally:
        timer.stop()


# ---------------------------------------------------------------------------
# Windows-only helpers (the WinCI arms; skipped off Windows)
# ---------------------------------------------------------------------------


def _require_windows() -> None:
    if host_platform() != "win32":
        pytest.skip("Windows only")


def _system_powershell_path() -> str:
    """The system PowerShell path from the module under test (Windows only)."""
    from s19_app.tui import os_clipboard_input as mod

    path = mod._system_powershell()
    if not path:
        pytest.skip("system PowerShell not found on this host")
    return path


def other_program_write(text: str) -> None:
    """A separate system PowerShell ``Set-Clipboard`` with the text on stdin
    (stands for "another Windows program")."""
    _require_windows()
    path = _system_powershell_path()
    subprocess.run(
        [path, "-NoProfile", "-NonInteractive", "-Command",
         "[Console]::InputEncoding=[System.Text.Encoding]::UTF8;$input | Set-Clipboard"],
        input=text, capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=10.0, shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def other_program_read() -> str:
    """A separate system PowerShell ``Get-Clipboard -Raw`` (UTF-8 output)."""
    _require_windows()
    path = _system_powershell_path()
    result = subprocess.run(
        [path, "-NoProfile", "-NonInteractive", "-Command",
         "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;Get-Clipboard -Raw"],
        capture_output=True, text=True, encoding="utf-8",
        errors="replace", timeout=10.0, shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.stdout.rstrip("\r\n")


def _own_write(text: str) -> bool:
    """Write a ``CF_UNICODETEXT`` with the test's own Win32 code (UTF-16), so
    a lone surrogate survives; ``True`` on success."""
    _require_windows()
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
    data = text.encode("utf-16-le", "surrogatepass") + b"\x00\x00"
    handle = kernel32.GlobalAlloc(0x0002, len(data))
    if not handle:
        return False
    pointer = kernel32.GlobalLock(handle)
    if not pointer:
        return False
    ctypes.memmove(pointer, data, len(data))
    kernel32.GlobalUnlock(handle)
    if not user32.OpenClipboard(None):
        return False
    try:
        user32.EmptyClipboard()
        return bool(user32.SetClipboardData(13, handle))
    finally:
        user32.CloseClipboard()


def own_read() -> str:
    """Read the clipboard with the test's own Win32 code (one read)."""
    _require_windows()
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalUnlock.restype = wintypes.BOOL
    if not user32.OpenClipboard(None):
        return None
    try:
        handle = user32.GetClipboardData(13)
        if not handle:
            return None
        pointer = kernel32.GlobalLock(handle)
        if not pointer:
            return None
        try:
            return ctypes.wstring_at(pointer)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def clipboard_sequence_number() -> int:
    """``GetClipboardSequenceNumber()`` (Own-read detection of a copy's end)."""
    _require_windows()
    import ctypes

    return int(ctypes.windll.user32.GetClipboardSequenceNumber())
