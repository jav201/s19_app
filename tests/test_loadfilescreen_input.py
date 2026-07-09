"""Regression tests for ``LoadFileScreen`` keyboard input handling.

These tests exist because two user-visible bugs in the Load dialog Input
survived the entire test suite:

    1. Typing a path was truncated at the App-level binding characters
       (``s``, ``e``, ``r``, ``l``, ``p``, ``j``, ``g``, ``q``, and every
       single-key binding declared on ``S19TuiApp.BINDINGS``) because the
       stock ``ModalScreen`` default-focus resolution landed on the
       ``#load_ok`` primary ``Button`` rather than the ``#load_path``
       ``Input``. Buttons do not accept letter keys, so the events bubbled
       up to the App where each bound letter fired its action instead of
       entering the field.

    2. Pasting a path copied in another OS process (Ctrl+V after an
       external clipboard copy) inserted nothing because Textual's stock
       ``Input.action_paste`` reads ``self.app.clipboard`` — a purely
       in-process buffer that is only populated by ``copy_to_clipboard``
       from inside the app. In a terminal that has negotiated the Kitty
       keyboard protocol (Textual's Windows driver enables it before
       bracketed paste), Windows Terminal forwards Ctrl+V as a plain key
       event rather than converting it to bracketed paste, so the
       clipboard-agnostic ``_on_paste`` handler is never invoked.

Both bugs shipped for months because the requirement set treated the
Load dialog as `Validation: Manual` and no automated coverage existed for
its keyboard behavior. These tests are the trip-wire.

Covers R-TUI-043 (initial focus + input handling of ``LoadFileScreen``)
and lifts R-A2L-004 to `Automated`.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from textual.widgets import Button, Input

from s19_app.tui.app import S19TuiApp
from s19_app.tui.os_clipboard_input import OsClipboardInput
from s19_app.tui.screens import LoadFileScreen

# A realistic Windows path chosen to hit every single-key App binding
# that would silently steal a keystroke if the focus were on the primary
# button instead of the Input. The colliding letters are:
#   s -> action_save_project
#   e -> action_show_entropy
#   r -> action_refresh_files
#   l -> action_load_file
#   p -> action_load_project
#   j -> action_dump_a2l_json
#   g -> action_focus_goto
#   b -> action_before_after_report
#   t -> action_view_reports
#   x -> action_operations_view
#   k -> action_show_legend
#   v -> action_select_variant
#   o -> action_open_workarea
#   1..8 -> action_show_screen(...)
#   . / , / + / - / /  -> paging / find
# The single character we DO NOT include is ``q`` (which fires
# ``action_quit`` and would tear down the test harness).
_COLLIDING_PATH = (
    "C:\\Users\\jjgh8\\OneDrive\\Documents\\Github\\s19_app"
    "\\examples\\case_01_basic_valid\\firmware.s19"
)


def _key_for(ch: str) -> str:
    special = {
        "\\": "backslash",
        "/": "slash",
        ":": "colon",
        ".": "full_stop",
        " ": "space",
        "-": "minus",
        "_": "underscore",
    }
    return special.get(ch, ch)


def test_loadfilescreen_auto_focus_lands_on_input(tmp_path: Path) -> None:
    """R-TUI-043-a: opening the modal must focus ``#load_path``, not a button.

    If this ever fails, typing into the field silently drops most letters
    to App-level bindings — the bug the user reported.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(8):
                await pilot.pause()
            focused = app.focused
            return f"{type(focused).__name__}:{getattr(focused, 'id', None)}"

    focused_repr = asyncio.run(_drive())
    assert focused_repr == "OsClipboardInput:load_path", (
        f"LoadFileScreen must auto-focus #load_path; focus went to {focused_repr}. "
        "Without this, keystrokes fire App bindings instead of typing."
    )


def test_loadfilescreen_typing_a_realistic_path_is_not_truncated(
    tmp_path: Path,
) -> None:
    """R-TUI-043-b: every char of a realistic path must land in the Input.

    Fails on the pre-fix layout because letters that match App bindings
    (``s``, ``e``, ``r``, ``l``, ``p``, ``j``, ``g``, ``o``, ``k``, ``e``,
    ``b``, ``t``, ``x``, ``v``) get consumed by the App while focus sits
    on the primary button.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            input_widget = app.screen.query_one("#load_path", Input)
            for ch in _COLLIDING_PATH:
                await pilot.press(_key_for(ch))
                await pilot.pause()
            return input_widget.value

    value = asyncio.run(_drive())
    assert value == _COLLIDING_PATH, (
        f"Typing was truncated:\n  expected: {_COLLIDING_PATH!r}\n"
        f"  got     : {value!r}"
    )


def test_loadfilescreen_typing_after_focus_stolen_by_button_reproduces_bug(
    tmp_path: Path,
) -> None:
    """Negative case: with focus forced to the button, characters DO drop.

    This is the reproduction test — it must PASS (i.e. characters get
    lost) so we know our positive test above is meaningful. If Textual
    ever changes so that a focused Button forwards letters back to the
    Input, this test failing tells us the guard is no longer needed.
    """

    async def _drive() -> tuple[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        lost = 0
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            # Manually steal focus (simulate the pre-fix default).
            app.screen.query_one("#load_ok", Button).focus()
            await pilot.pause()

            input_widget = app.screen.query_one("#load_path", Input)
            for ch in _COLLIDING_PATH:
                # Skip ``q`` which would quit the app.
                if _key_for(ch) == "q":
                    lost += 1
                    continue
                if not isinstance(app.screen, LoadFileScreen):
                    # Some binding pushed a new screen — that is ALSO a
                    # symptom of the bug. Count remaining as lost.
                    lost += len(_COLLIDING_PATH) - _COLLIDING_PATH.index(ch)
                    break
                before = input_widget.value
                try:
                    await pilot.press(_key_for(ch))
                    await pilot.pause()
                except Exception:
                    lost += 1
                    continue
                if not input_widget.value.endswith(ch):
                    lost += 1
            return input_widget.value, lost

    value, lost = asyncio.run(_drive())
    assert lost >= 5, (
        f"With focus stolen by the Load button, at least 5 chars should be "
        f"lost (App-binding letters + button-swallowed letters). "
        f"Got lost={lost}, final value={value!r}. "
        "If this reproduces zero losses, Textual's Button semantics changed "
        "and the R-TUI-043 guard may no longer be needed."
    )


def test_loadfilescreen_uses_os_clipboard_widget(tmp_path: Path) -> None:
    """R-TUI-043-c: the Load dialog Input must be the OS-clipboard variant.

    Fails if someone replaces ``OsClipboardInput`` with a stock ``Input``
    in ``LoadFileScreen.compose``, restoring the OS-clipboard-blind
    ``action_paste`` behavior.
    """

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            widget = app.screen.query_one("#load_path", Input)
            return type(widget).__name__

    widget_type = asyncio.run(_drive())
    assert widget_type == "OsClipboardInput", (
        f"LoadFileScreen must use OsClipboardInput for #load_path so Ctrl+V "
        f"pastes from the OS clipboard; got {widget_type}."
    )


def test_loadfilescreen_ctrl_v_reads_from_os_clipboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TUI-043-d: Ctrl+V must consult the OS clipboard, not just the internal buffer.

    Uses monkeypatching on ``read_os_clipboard`` so the test does not
    depend on the real OS clipboard (which is shared with the developer's
    workstation and would be flaky).
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    monkeypatch.setattr(
        os_clip_mod, "read_os_clipboard", lambda: "PATH_FROM_OS_CLIPBOARD"
    )

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            input_widget = app.screen.query_one("#load_path", Input)
            await pilot.press("ctrl+v")
            await pilot.pause()
            return input_widget.value

    value = asyncio.run(_drive())
    assert value == "PATH_FROM_OS_CLIPBOARD", (
        f"Ctrl+V must insert text from the OS clipboard (via "
        f"read_os_clipboard). Got: {value!r}"
    )


def test_loadfilescreen_ctrl_v_falls_back_to_internal_clipboard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TUI-043-e: when the OS clipboard read fails, fall back to the internal buffer.

    Regressions here would break paste on systems without Tk available or
    when another process is holding the clipboard exclusively.
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    monkeypatch.setattr(os_clip_mod, "read_os_clipboard", lambda: None)

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "PATH_FROM_INTERNAL_FALLBACK"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            input_widget = app.screen.query_one("#load_path", Input)
            await pilot.press("ctrl+v")
            await pilot.pause()
            return input_widget.value

    value = asyncio.run(_drive())
    assert value == "PATH_FROM_INTERNAL_FALLBACK", (
        f"Ctrl+V must fall back to app.clipboard when the OS read fails. "
        f"Got: {value!r}"
    )


def test_os_clipboard_input_is_input_subclass() -> None:
    """R-TUI-043-f: OsClipboardInput must remain a drop-in Input subclass.

    Guards against a refactor that breaks the class hierarchy (any code
    doing ``query_one("#load_path", Input)`` would silently miss it).
    """
    assert issubclass(OsClipboardInput, Input), (
        "OsClipboardInput must subclass Input so widget queries "
        "targeting Input still find it."
    )


# ---------------------------------------------------------------------------
# R-TUI-043-g/h/i/j — Layered clipboard cascade (tkinter → ctypes → PowerShell).
#
# The cascade guarantees that a single layer's failure mode (Tcl grab race,
# antivirus lock, PowerShell missing) does not silently break Ctrl+V. Each
# test below exercises the cascade at the ``read_os_clipboard`` level with
# fake strategy callables so nothing depends on the real OS clipboard.
# ---------------------------------------------------------------------------


def test_read_os_clipboard_happy_path_uses_only_first_strategy() -> None:
    """R-TUI-043-g: on happy path, ONLY the first strategy is invoked.

    Perf sanity: we do not pay the cost of the fallback layers when the
    primary layer returns text. Guards against a refactor that
    accidentally invokes every layer every time.
    """
    from s19_app.tui.os_clipboard_input import read_os_clipboard

    calls: list[str] = []

    def tk_ok() -> str:
        calls.append("tk")
        return "TK_TEXT"

    def ctypes_boom() -> str:
        calls.append("ctypes")
        raise RuntimeError("must-not-be-called on happy path")

    def ps_boom() -> str:
        calls.append("ps")
        raise RuntimeError("must-not-be-called on happy path")

    result = read_os_clipboard(
        strategies=(("tkinter", tk_ok), ("ctypes-win32", ctypes_boom), ("powershell", ps_boom))
    )
    assert result == "TK_TEXT"
    assert calls == ["tk"], f"Only the first strategy should run; got {calls}"


def test_read_os_clipboard_cascades_tk_fail_to_ctypes() -> None:
    """R-TUI-043-h: when tkinter returns None, the cascade tries ctypes next."""
    from s19_app.tui.os_clipboard_input import read_os_clipboard

    calls: list[str] = []
    result = read_os_clipboard(
        strategies=(
            ("tkinter", lambda: (calls.append("tk") or None)),
            ("ctypes-win32", lambda: (calls.append("ct") or "CTYPES_TEXT")),
            ("powershell", lambda: (calls.append("ps") or "PS_TEXT")),
        )
    )
    assert result == "CTYPES_TEXT"
    assert calls == ["tk", "ct"], (
        f"Cascade should stop at the first non-None; got calls={calls}"
    )


def test_read_os_clipboard_cascades_tk_and_ctypes_fail_to_powershell() -> None:
    """R-TUI-043-i: when tk AND ctypes fail, PowerShell is the last resort."""
    from s19_app.tui.os_clipboard_input import read_os_clipboard

    calls: list[str] = []
    result = read_os_clipboard(
        strategies=(
            ("tkinter", lambda: (calls.append("tk") or None)),
            ("ctypes-win32", lambda: (calls.append("ct") or None)),
            ("powershell", lambda: (calls.append("ps") or "PS_RESCUE")),
        )
    )
    assert result == "PS_RESCUE"
    assert calls == ["tk", "ct", "ps"], (
        f"All three layers must be tried in order; got calls={calls}"
    )


def test_read_os_clipboard_returns_none_when_all_layers_fail() -> None:
    """R-TUI-043-j: total cascade failure yields ``None`` (never raises)."""
    from s19_app.tui.os_clipboard_input import read_os_clipboard

    result = read_os_clipboard(
        strategies=(
            ("tkinter", lambda: None),
            ("ctypes-win32", lambda: None),
            ("powershell", lambda: None),
        )
    )
    assert result is None


def test_read_os_clipboard_swallows_strategy_exceptions() -> None:
    """R-TUI-043-k: a strategy that raises must NOT propagate; cascade continues."""
    from s19_app.tui.os_clipboard_input import read_os_clipboard

    def boom() -> str:
        raise TimeoutError("subprocess timeout")

    result = read_os_clipboard(
        strategies=(
            ("tkinter", lambda: None),
            ("ctypes-win32", boom),
            ("powershell", lambda: "PS_AFTER_BOOM"),
        )
    )
    assert result == "PS_AFTER_BOOM"


def test_ctrl_v_notifies_user_when_every_clipboard_source_is_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TUI-043-l: on total clipboard failure, the user gets a warning notification.

    Without this the paste is a silent no-op and the user has no idea why
    Ctrl+V did nothing.
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    # Force the OS clipboard cascade to return None so we hit the empty
    # internal-fallback branch.
    monkeypatch.setattr(os_clip_mod, "read_os_clipboard", lambda: None)

    notifications: list[tuple[str, str]] = []

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = ""  # internal clipboard also empty
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            app.push_screen(LoadFileScreen())
            for _ in range(6):
                await pilot.pause()
            # Patch notify to record the call instead of routing to the
            # real notification widget (which does not exist in this
            # headless test context in some Textual builds).
            original_notify = app.notify

            def _capture(msg: str, *, severity: str = "information", **kwargs) -> None:  # type: ignore[no-redef]
                notifications.append((severity, msg))
                # Also drive the real notify to catch any exceptions.
                try:
                    original_notify(msg, severity=severity, **kwargs)
                except Exception:
                    pass

            app.notify = _capture  # type: ignore[method-assign]

            input_widget = app.screen.query_one("#load_path", Input)
            input_widget.value = "initial"  # sanity: paste must not corrupt
            await pilot.press("ctrl+v")
            await pilot.pause()
            return input_widget.value

    value_after = asyncio.run(_drive())
    assert value_after == "initial", (
        f"Failed paste must not corrupt the Input value; got {value_after!r}"
    )
    assert any(sev == "warning" and "clipboard" in msg.lower() for sev, msg in notifications), (
        f"Expected a warning notification about clipboard; got {notifications!r}"
    )


def test_powershell_layer_does_not_require_wt_or_windows_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-TUI-043-m: the PowerShell fallback must invoke ``powershell.exe`` only.

    On a machine without Windows Terminal (``wt``) or the more modern
    ``pwsh``, the fallback must still work because ``powershell.exe``
    ships with every Windows install. We inspect the argv the layer
    would use rather than actually executing.
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    captured: dict[str, list[str]] = {}

    class _FakeResult:
        returncode = 0
        stdout = "PS_CLIPBOARD_TEXT\r\n"
        stderr = ""

    def _fake_run(argv, **kwargs) -> _FakeResult:  # type: ignore[no-untyped-def]
        captured["argv"] = list(argv)
        captured["kwargs"] = list(kwargs.keys())
        return _FakeResult()

    monkeypatch.setattr(os_clip_mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(os_clip_mod.sys, "platform", "win32")

    text = os_clip_mod._read_via_powershell()
    assert text == "PS_CLIPBOARD_TEXT"
    assert captured["argv"][0] == "powershell", (
        f"PowerShell layer must invoke `powershell` (not `wt` or `pwsh`); "
        f"got {captured['argv']!r}"
    )
    assert "timeout" in captured["kwargs"], (
        "PowerShell layer must set a timeout to prevent hangs"
    )


def test_powershell_layer_returns_none_on_non_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-TUI-043-n: the PowerShell layer is a no-op on non-Windows platforms."""
    from s19_app.tui import os_clipboard_input as os_clip_mod

    monkeypatch.setattr(os_clip_mod.sys, "platform", "linux")

    called: list[bool] = []

    def _should_not_run(*args, **kwargs):  # type: ignore[no-untyped-def]
        called.append(True)
        raise RuntimeError("must not spawn powershell on non-Windows")

    monkeypatch.setattr(os_clip_mod.subprocess, "run", _should_not_run)
    assert os_clip_mod._read_via_powershell() is None
    assert called == []


def test_ctypes_layer_returns_none_on_non_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """R-TUI-043-o: the ctypes-Win32 layer is a no-op on non-Windows platforms."""
    from s19_app.tui import os_clipboard_input as os_clip_mod

    monkeypatch.setattr(os_clip_mod.sys, "platform", "linux")
    assert os_clip_mod._read_via_ctypes() is None


def test_notification_message_mentions_ctrl_shift_v_workaround(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """R-TUI-043-p: the failure notification points the user at Ctrl+Shift+V.

    The whole point of the notification is to route the user to the
    OS-level workaround. If the message stops mentioning it, the fix is
    half-useless.
    """
    from s19_app.tui import os_clipboard_input as os_clip_mod

    assert "Ctrl+Shift+V" in os_clip_mod._PASTE_FAIL_NOTIFICATION, (
        "Failure notification must document the WT-level paste shortcut"
    )
