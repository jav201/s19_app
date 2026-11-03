"""TC-B102-01..08 — batch-102 Inc 1 — OS clipboard copy/paste (tester E4).

Pins the Inc-1 slice designed in
``.dev-flow/2026-11-03-batch-102/inc-1/{01-requirements.md,02-test-cases.md,codewire-graph.md}``
plus the mandatory Inc-1 addendas of
``.dev-flow/2026-11-03-batch-102/design/E3-rulings-inc1-inc2.md``:

* TC-B102-01 — paste inserts the OS clipboard text at the three
  representative surfaces (Load ``#load_path``, A2L ``#a2l_tags_filter_input``,
  Patch paste ``#patch_paste_text``); over-cap payloads truncate at 65,536.
* TC-B102-02 — copy writes the selection to the OS clipboard through
  ``write_os_clipboard`` (Win32 → Tk → PowerShell cascade, first success
  wins, total failure yields ``False``) without mutating the widget; the
  internal clipboard mirrors the same text, capped at 65,536 both ways
  (E3 addendum 3).
* TC-B102-03 — cut writes the OS payload and removes the selection on both
  widget classes; an ``OsClipboardInput`` cut with an empty selection raises
  ``SkipAction`` and must not wipe the internal clipboard with ``""``
  (E3 addendum 2).
* TC-B102-04/05 — the real PowerShell read/write rescues run under a
  ``>= 2.0`` s subprocess timeout (recorded by a ``subprocess.run`` fake),
  with a static command, ``shell=False`` and a hidden-window creation flag
  (E3 addendum 5); the write layer passes the payload via stdin,
  never interpolated into ``-Command``.
* TC-B102-06 — total OS write failure degrades to the internal clipboard
  and paints the exact warning
  ``Clipboard write failed — copied inside the app only.``
* TC-B102-07 — total paste failure selects the current field text and
  paints the exact read warning
  ``Clipboard read failed — try Ctrl+Shift+V or type the path manually.``
* TC-B102-08 — an empty-selection cut on ``CappedTextArea`` keeps Textual's
  line-cut (``_delete_cursor_line``) while writing the replaced line text
  to the OS and internal clipboards.

RED-phase discipline: every symbol the increment adds (``write_os_clipboard``,
``_write_via_powershell``, the async ``action_copy`` / ``action_cut``
overrides and the OS-reading ``CappedTextArea.action_paste``) is referenced
lazily inside the test that needs it, so this module still COLLECTS on the
pre-increment tree and each test fails there on its own behavioural reason
(a failed assertion, a ``DID NOT RAISE``, or the ``ImportError`` of a symbol
the new design adds) — never on a syntax or collection error. Widget actions
are invoked through :func:`_invoke`, which tolerates the still-sync
inherited actions during RED and awaits the async overrides once they land.
"""

from __future__ import annotations

import asyncio
import inspect
import subprocess
from pathlib import Path

import pytest
from textual.app import App, ComposeResult
from textual.screen import SkipAction
from textual.widgets import Input, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui.capped_text_area import CappedTextArea
from s19_app.tui.os_clipboard_input import (
    _CLIPBOARD_READ_CAP_CHARS as _READ_CAP,
)
from s19_app.tui.os_clipboard_input import OsClipboardInput
from tests.support.b100_load_dialog import bare_path_dialog

#: Contract literals from 01-requirements.md — asserted verbatim, never
#: imported as constants, so a rename in the product cannot silently weaken
#: the user-visible message.
_READ_FAIL_WARNING = (
    "Clipboard read failed — try Ctrl+Shift+V or type the path manually."
)
_WRITE_FAIL_WARNING = "Clipboard write failed — copied inside the app only."

#: The 65,536-char cap as a contract literal for the WRITE side (E3
#: addendum 3 pins the OS payload and the internal mirror to the same cap;
#: addendum 6 warns the module-level READ constant may be renamed for the
#: write path, so the write oracle binds to the number, not the name).
_WRITE_CAP = 65536

#: Representative paste surfaces (02-test-cases.md "Superficies de
#: aceptación") mapped to the rail key that reveals their container.
_PASTE_SURFACES = {
    "load_path": None,  # pushed as a modal Load dialog
    "a2l_tags_filter_input": "a2l",
    "patch_paste_text": "patch",
}


class _ClipboardHarness(App):
    """Minimal app hosting one ``OsClipboardInput`` and one ``CappedTextArea``."""

    def compose(self) -> ComposeResult:
        yield OsClipboardInput("", id="ci")
        yield CappedTextArea("", id="ta")


class _FakeCompleted:
    """Stand-in for ``subprocess.CompletedReturned`` from a faked ``run``."""

    def __init__(
        self, returncode: int = 0, stdout: str = "", stderr: str = ""
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ---------------------------------------------------------------------------
# Seams. The widgets may resolve the clipboard helpers from either
# ``os_clipboard_input`` (where they live today) or ``capped_text_area``
# (if the TextArea override imports the names), so both module attributes
# are patched; ``setattr`` simply creates the attribute when absent, which
# is harmless on the pre-increment tree.
# ---------------------------------------------------------------------------


def _patch_os_read(monkeypatch: pytest.MonkeyPatch, value: str | None) -> None:
    """Force the OS-read cascade to return ``value`` on both widget classes.

    ``raising=False`` keeps the seam RED-safe: on the pre-increment tree
    the attribute does not exist on one of the modules yet, and the test
    must still reach its behavioural assertions.
    """
    from s19_app.tui import capped_text_area as cta_mod
    from s19_app.tui import os_clipboard_input as oci_mod

    monkeypatch.setattr(
        oci_mod, "read_os_clipboard", lambda *a, **k: value, raising=False
    )
    monkeypatch.setattr(
        cta_mod, "read_os_clipboard", lambda *a, **k: value, raising=False
    )


def _inject_read_strategies(monkeypatch: pytest.MonkeyPatch, blob: str) -> None:
    """Inject ``blob`` BELOW ``read_os_clipboard`` (at ``_STRATEGIES``).

    The real bounded funnel runs inside ``action_paste`` this way, so the
    65,536-char cap is genuinely exercised (repo seam discipline from
    test_loadfilescreen_input.py AT-042b: never monkeypatch the funnel).
    """
    from s19_app.tui import capped_text_area as cta_mod
    from s19_app.tui import os_clipboard_input as oci_mod

    fake = (("fake-os", lambda: blob),)
    monkeypatch.setattr(oci_mod, "_STRATEGIES", fake, raising=False)
    monkeypatch.setattr(cta_mod, "_STRATEGIES", fake, raising=False)


def _recording_writer(
    monkeypatch: pytest.MonkeyPatch, result: bool
) -> list:
    """Replace ``write_os_clipboard`` everywhere with a recording fake.

    Returns the list the fake appends every payload to, so a test can
    assert the exact OS payload (and that the cascade was attempted).
    """
    from s19_app.tui import capped_text_area as cta_mod
    from s19_app.tui import os_clipboard_input as oci_mod

    recorded: list = []

    def _fake_write(text, *args, **kwargs):
        recorded.append(text)
        return result

    monkeypatch.setattr(oci_mod, "write_os_clipboard", _fake_write, raising=False)
    monkeypatch.setattr(cta_mod, "write_os_clipboard", _fake_write, raising=False)
    return recorded


def _capture_notify(app: App, sink: list) -> None:
    """Record ``(severity, message)`` for every ``app.notify`` call."""

    original = app.notify

    def _spy(message: str, *, severity: str = "information", **kwargs) -> None:
        sink.append((severity, str(message)))
        try:
            original(message, severity=severity, **kwargs)
        except Exception:
            pass

    app.notify = _spy  # type: ignore[method-assign]


async def _invoke(widget, action: str) -> None:
    """Invoke a widget action, awaiting it only when it is awaitable.

    During RED the inherited Textual actions are still synchronous; once
    the increment lands they are async. Tolerating both keeps the RED
    failures behavioural (assertions) instead of ``TypeError`` noise, and
    the tests need no rework at GREEN.
    """
    result = getattr(widget, action)()
    if inspect.isawaitable(result):
        await result


# ---------------------------------------------------------------------------
# Widget accessors shared by the harness tests.
# ---------------------------------------------------------------------------


def _widget(app: App, kind: str):
    return app.query_one(
        "#ci" if kind == "input" else "#ta",
        OsClipboardInput if kind == "input" else CappedTextArea,
    )


def _content(widget) -> str:
    return widget.value if isinstance(widget, Input) else widget.text


def _set_content(widget, kind: str, text: str) -> None:
    if kind == "input":
        widget.value = text
    else:
        widget.text = text


def _select_range(widget, kind: str, start: int, end: int) -> None:
    """Select ``[start, end)`` on a single-line widget of either class."""
    if kind == "input":
        widget.selection = (start, end)
    else:
        widget.selection = ((0, start), (0, end))


def _assert_hidden_window(kwargs: dict) -> None:
    """E3 addendum 5: the PowerShell layer must request a hidden window."""
    creationflags = kwargs.get("creationflags")
    assert creationflags is not None, (
        f"The PowerShell clipboard subprocess must pass creationflags to "
        f"request a hidden window on Windows; kwargs={sorted(kwargs)}"
    )
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        assert creationflags & subprocess.CREATE_NO_WINDOW, (
            "The CREATE_NO_WINDOW bit must be set so no console window "
            f"flashes; creationflags={creationflags!r}"
        )


# ---------------------------------------------------------------------------
# TC-B102-01 — paste inserts the current OS clipboard text on the
# representative surfaces; the internal clipboard is not consulted first.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "widget_id",
    sorted(_PASTE_SURFACES),
    ids=sorted(_PASTE_SURFACES),
)
def test_tc_b102_01_paste_inserts_os_clipboard_text_on_representative_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, widget_id: str
) -> None:
    """TC-B102-01 (R-B102-CLIP-001): Ctrl+V lands OS text on all 3 surfaces.

    Drives the REAL key path (focus + ctrl+v) per surface with the OS read
    faked to ``C:\\tmp\\firmware.s19`` and the internal clipboard seeded
    with a decoy: if the action read ``App.clipboard`` first (the mutant
    control), the decoy would win and this fails. The Load and A2L-filter
    surfaces already paste from the OS (batch-67 contract this increment
    extends); the Patch paste buffer is the new coverage and is RED on the
    pre-increment tree (stock sync ``action_paste`` reads the decoy).
    """
    os_text = "C:\\tmp\\firmware.s19"
    _patch_os_read(monkeypatch, os_text)
    rail_key = _PASTE_SURFACES[widget_id]

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        app._clipboard = "INTERNAL_DECOY_MUST_NOT_WIN"
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause()
            if rail_key is None:
                app.push_screen(bare_path_dialog())
                for _ in range(6):
                    await pilot.pause()
            else:
                app.action_show_screen(rail_key)
                for _ in range(3):
                    await pilot.pause()
            widget = (
                app.screen if rail_key is None else app
            ).query_one(
                f"#{widget_id}",
                TextArea if widget_id == "patch_paste_text" else Input,
            )
            widget.focus()
            await pilot.pause()
            await pilot.press("ctrl+v")
            await pilot.pause()
            await pilot.pause()
            return _content(widget)

    result = asyncio.run(_drive())
    assert os_text in result, (
        f"Ctrl+V on #{widget_id} must insert the OS clipboard text "
        f"{os_text!r}; got {result!r}"
    )
    assert "INTERNAL_DECOY" not in result, (
        f"Ctrl+V on #{widget_id} must not consult App.clipboard first — "
        f"the internal decoy won over the OS clipboard: {result!r}"
    )


@pytest.mark.parametrize("kind", ["input", "textarea"], ids=["input", "textarea"])
def test_tc_b102_01_over_cap_paste_is_capped_at_65536(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """TC-B102-01 (R-B102-CLIP-001): payloads past 65,536 chars truncate.

    Injection at ``_STRATEGIES`` keeps the real bounded
    ``read_os_clipboard`` funnel in the loop, so the cap cannot be
    bypassed by a fake at the funnel. RED on the pre-increment tree for
    the TextArea arm (its paste override does not exist yet).
    """
    blob = "A" * (_READ_CAP + 5000)
    _inject_read_strategies(monkeypatch, blob)

    async def _drive() -> str:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            widget = _widget(app, kind)
            widget.focus()
            await pilot.pause()
            await _invoke(widget, "action_paste")
            await pilot.pause()
            return _content(widget)

    result = asyncio.run(_drive())
    assert result == blob[:_READ_CAP], (
        f"Paste must cap the OS payload at {_READ_CAP} chars; "
        f"got {len(result)} chars"
    )


# ---------------------------------------------------------------------------
# TC-B102-02 — copy writes the selection to OS + internal clipboards
# without mutating the widget; write cascade order; write-side cap.
# ---------------------------------------------------------------------------


_COPY_VALUE = "C:\\tmp\\firmware.a2l"
_COPY_SELECTION = "firmware.a2l"  # value[7:19]


@pytest.mark.parametrize("kind", ["input", "textarea"], ids=["input", "textarea"])
def test_tc_b102_02_copy_writes_selection_to_os_and_internal_without_mutation(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """TC-B102-02 (R-B102-CLIP-002): copy payload is exact, widget untouched.

    The OS write strategies are replaced by a recording fake so the test
    never touches the developer's real clipboard; the internal mirror must
    hold the same text and ``value``/``selection`` must be unchanged.
    RED on the pre-increment tree: the inherited sync action never
    reaches the (not yet existing) OS write, so no payload is recorded.
    """
    recorded = _recording_writer(monkeypatch, result=True)

    async def _drive() -> tuple:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            widget = _widget(app, kind)
            _set_content(widget, kind, _COPY_VALUE)
            _select_range(widget, kind, 7, 19)
            before_selection = widget.selection
            await pilot.pause()
            await _invoke(widget, "action_copy")
            await pilot.pause()
            return _content(widget), widget.selection, before_selection, app.clipboard

    content, selection, before_selection, internal = asyncio.run(_drive())
    assert recorded == [_COPY_SELECTION], (
        f"The OS clipboard write must carry exactly {_COPY_SELECTION!r}; "
        f"recorded payloads: {recorded!r}"
    )
    assert content == _COPY_VALUE, (
        f"Copy must not modify the editable text; got {content!r}"
    )
    assert tuple(selection) == tuple(before_selection), (
        f"Copy must not modify the selection; got {selection!r}"
    )
    assert internal == _COPY_SELECTION, (
        f"The internal clipboard must mirror the copied text; "
        f"got {internal!r}"
    )


@pytest.mark.parametrize("kind", ["input", "textarea"], ids=["input", "textarea"])
def test_tc_b102_02_copy_caps_os_payload_and_internal_mirror(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """TC-B102-02 + E3 addendum 3: the 65,536 cap binds OS payload AND mirror.

    A selection of ``_WRITE_CAP + 500`` chars must reach the OS writer (and
    the internal clipboard) truncated to exactly ``_WRITE_CAP`` — the cap
    is one contract for both destinations, not two.
    """
    recorded = _recording_writer(monkeypatch, result=True)
    big = "B" * (_WRITE_CAP + 500)

    async def _drive() -> str:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            widget = _widget(app, kind)
            _set_content(widget, kind, big)
            _select_range(widget, kind, 0, len(big))
            await pilot.pause()
            await _invoke(widget, "action_copy")
            await pilot.pause()
            return app.clipboard

    internal = asyncio.run(_drive())
    assert recorded, "the OS write cascade must have been attempted"
    assert len(recorded[0]) == _WRITE_CAP, (
        f"The OS payload must be capped at {_WRITE_CAP} chars; "
        f"got {len(recorded[0])}"
    )
    assert recorded[0] == big[:_WRITE_CAP]
    assert internal == big[:_WRITE_CAP], (
        f"The internal mirror must be capped at {_WRITE_CAP} chars too; "
        f"got {len(internal)}"
    )


def test_tc_b102_02_write_os_clipboard_cascade_order() -> None:
    """TC-B102-02 (codewire ``write_os_clipboard``): Win32 → Tk → PS order.

    First success short-circuits the cascade; a raising strategy counts as
    a failed layer and the cascade continues; every layer failing yields
    ``False``. Imported lazily — the symbol is added by this increment.
    """
    from s19_app.tui.os_clipboard_input import write_os_clipboard

    calls: list = []

    def layer(name, result=None, boom=False):
        def _f(_text: str) -> object:
            calls.append(name)
            if boom:
                raise RuntimeError(f"{name} exploded")
            return result

        return _f

    strategies = (
        ("win32", layer("win32", True)),
        ("tk", layer("tk", True)),
        ("powershell", layer("powershell", True)),
    )
    assert write_os_clipboard("payload", strategies=strategies) is True
    assert calls == ["win32"], (
        "Win32 is the persistent-write layer and must be tried FIRST; "
        f"calls={calls}"
    )

    calls.clear()
    strategies = (
        ("win32", layer("win32", False)),
        ("tk", layer("tk", True)),
        ("powershell", layer("powershell", True)),
    )
    assert write_os_clipboard("payload", strategies=strategies) is True
    assert calls == ["win32", "tk"], f"calls={calls}"

    calls.clear()
    strategies = (
        ("win32", layer("win32", False)),
        ("tk", layer("tk", False)),
        ("powershell", layer("powershell", False)),
    )
    assert write_os_clipboard("payload", strategies=strategies) is False
    assert calls == ["win32", "tk", "powershell"], f"calls={calls}"

    calls.clear()
    strategies = (
        ("win32", layer("win32", boom=True)),
        ("tk", layer("tk", True)),
    )
    assert write_os_clipboard("payload", strategies=strategies) is True
    assert calls == ["win32", "tk"], (
        "A strategy exception must fail only that layer, never abort the "
        f"cascade; calls={calls}"
    )


# ---------------------------------------------------------------------------
# TC-B102-03 — cut writes the OS payload and removes the selection; the
# empty-selection Input cut is a SkipAction that preserves the internal
# clipboard (E3 addendum 2).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["input", "textarea"], ids=["input", "textarea"])
def test_tc_b102_03_cut_writes_os_and_removes_selection(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """TC-B102-03 (R-B102-CLIP-003): payload ``DE AD``, text left `` BE EF``."""
    recorded = _recording_writer(monkeypatch, result=True)

    async def _drive() -> tuple:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            widget = _widget(app, kind)
            _set_content(widget, kind, "DE AD BE EF")
            _select_range(widget, kind, 0, 5)
            await pilot.pause()
            await _invoke(widget, "action_cut")
            await pilot.pause()
            return _content(widget), app.clipboard

    content, internal = asyncio.run(_drive())
    assert recorded == ["DE AD"], (
        f"The OS clipboard write must carry exactly 'DE AD'; "
        f"recorded payloads: {recorded!r}"
    )
    assert "DE AD" not in content, (
        f"Cut must remove the selection from the editable text; "
        f"got {content!r}"
    )
    assert content == " BE EF", f"got {content!r}"
    assert internal == "DE AD", f"internal clipboard: {internal!r}"


def test_tc_b102_03_input_empty_selection_cut_skips_and_preserves_internal_clipboard() -> (
    None
):
    """E3 addendum 2 (R-B102-CLIP-003): empty Input cut is a no-op SkipAction.

    ``OsClipboardInput.action_cut`` with an empty selection must raise
    Textual's ``SkipAction`` and must NOT clear the internal clipboard by
    copying ``""`` into it. RED on the pre-increment tree: the inherited
    ``Input.action_cut`` copies the empty selection into ``App.clipboard``
    and never raises.
    """
    app_clipboard_before = "KEEP_ME"

    async def _drive() -> tuple:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            widget = app.query_one("#ci", OsClipboardInput)
            widget.value = "keep me"
            widget.selection = (0, 0)
            app._clipboard = app_clipboard_before
            await pilot.pause()
            with pytest.raises(SkipAction):
                await _invoke(widget, "action_cut")
            await pilot.pause()
            return widget.value, app.clipboard

    value, internal = asyncio.run(_drive())
    assert value == "keep me", f"An empty cut must not touch the value; got {value!r}"
    assert internal == app_clipboard_before, (
        f"An empty cut must not wipe the internal clipboard; got {internal!r}"
    )


# ---------------------------------------------------------------------------
# TC-B102-04/05 — the real PowerShell rescues under the enlarged timeout,
# static command, shell=False and hidden window (E3 addendum 5).
# ---------------------------------------------------------------------------


def test_tc_b102_04_powershell_read_rescue_uses_enlarged_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-B102-04 (R-B102-CLIP-005): read rescue gets >= 2.0 s.

    ``subprocess.run`` is faked to record its ``timeout`` and return
    ``OK_FROM_PS``; the tk/Win32 layers are irrelevant at this seam. The
    recorded timeout is the real budget the layer hands the subprocess —
    a 0.5 s residue (the mutant control) fails the assertion.
    """
    from s19_app.tui import os_clipboard_input as mod

    captured: dict = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = dict(kwargs)
        return _FakeCompleted(returncode=0, stdout="OK_FROM_PS\r\n", stderr="")

    monkeypatch.setattr(mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(mod.sys, "platform", "win32")

    text = mod._read_via_powershell()

    assert text == "OK_FROM_PS", f"got {text!r}"
    timeout = captured["kwargs"].get("timeout")
    assert timeout is not None and timeout >= 2.0, (
        f"The PowerShell read rescue must allow a cold process start of "
        f"at least 2.0 s; recorded timeout={timeout!r}"
    )
    assert mod._POWERSHELL_TIMEOUT_S >= 2.0, (
        f"_POWERSHELL_TIMEOUT_S must be >= 2.0; got {mod._POWERSHELL_TIMEOUT_S!r}"
    )
    argv = captured["argv"]
    assert argv[0] == "powershell", f"argv={argv!r}"
    assert any("Get-Clipboard" in str(part) for part in argv[1:]), (
        f"The read command must stay the static Get-Clipboard form; argv={argv!r}"
    )
    assert "OK_FROM_PS" not in " ".join(map(str, argv)), (
        "Clipboard-derived text must never be interpolated into the command."
    )
    assert captured["kwargs"].get("shell") is False, (
        f"The PowerShell subprocess must use shell=False; "
        f"kwargs={captured['kwargs']!r}"
    )
    _assert_hidden_window(captured["kwargs"])


def test_tc_b102_05_powershell_write_rescue_uses_enlarged_timeout_via_static_stdin_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-B102-05 (R-B102-CLIP-005): write rescue — 2.0 s, stdin payload.

    The copied text must reach PowerShell through the ``input`` (stdin)
    kwarg as UTF-8, never interpolated into ``-Command``; the command
    stays the static ``Set-Clipboard`` form; ``shell=False`` and a hidden
    window are requested (E3 addendum 5). Imported lazily — the layer is
    added by this increment, so RED is the ``ImportError``.
    """
    from s19_app.tui import os_clipboard_input as mod
    from s19_app.tui.os_clipboard_input import _write_via_powershell

    captured: dict = {}

    def _fake_run(argv, **kwargs):
        captured["argv"] = list(argv)
        captured["kwargs"] = dict(kwargs)
        return _FakeCompleted(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(mod.subprocess, "run", _fake_run)
    monkeypatch.setattr(mod.sys, "platform", "win32")

    written = _write_via_powershell("payload")

    assert written is True, "exit 0 must yield a successful write"
    timeout = captured["kwargs"].get("timeout")
    assert timeout is not None and timeout >= 2.0, (
        f"The PowerShell write rescue must allow at least 2.0 s; "
        f"recorded timeout={timeout!r}"
    )
    argv = captured["argv"]
    assert any("Set-Clipboard" in str(part) for part in argv[1:]), (
        f"The write command must stay the static Set-Clipboard form; argv={argv!r}"
    )
    assert "payload" not in " ".join(map(str, argv)), (
        "The copied text must travel via stdin, never interpolated into -Command; "
        f"argv={argv!r}"
    )
    assert captured["kwargs"].get("input") == "payload", (
        f"The payload must be passed through the stdin kwarg; "
        f"kwargs={captured['kwargs']!r}"
    )
    assert captured["kwargs"].get("shell") is False, (
        f"The PowerShell subprocess must use shell=False; "
        f"kwargs={captured['kwargs']!r}"
    )
    _assert_hidden_window(captured["kwargs"])


# ---------------------------------------------------------------------------
# TC-B102-06 — total OS write failure degrades to the internal clipboard
# with the exact write warning.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["input", "textarea"], ids=["input", "textarea"])
def test_tc_b102_06_total_write_failure_falls_back_to_internal_with_exact_warning(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """TC-B102-06 (R-B102-CLIP-004): every OS write strategy fails.

    The internal clipboard still receives the selection, the local cut
    still happens, and the LATEST painted warning is exactly
    ``Clipboard write failed — copied inside the app only.`` at warning
    severity. The OS write seam is a fake that always fails; RED on the
    pre-increment tree: the inherited sync actions never reach the seam.
    """
    recorded = _recording_writer(monkeypatch, result=False)
    notifications: list = []

    async def _drive() -> tuple:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            _capture_notify(app, notifications)
            widget = _widget(app, kind)
            _set_content(widget, kind, "DE AD BE EF")
            _select_range(widget, kind, 0, 5)
            await pilot.pause()
            await _invoke(widget, "action_copy")
            await pilot.pause()
            internal_after_copy = app.clipboard
            await _invoke(widget, "action_cut")
            await pilot.pause()
            return internal_after_copy, _content(widget), app.clipboard

    internal_after_copy, content_after_cut, internal_after_cut = asyncio.run(_drive())
    assert recorded, "the OS write cascade must have been attempted"
    assert internal_after_copy == "DE AD", (
        f"Internal mirror must survive a total OS write failure; "
        f"got {internal_after_copy!r}"
    )
    assert "DE AD" not in content_after_cut, (
        f"The local cut must happen even when every OS layer fails; "
        f"got {content_after_cut!r}"
    )
    assert internal_after_cut == "DE AD", f"got {internal_after_cut!r}"
    assert notifications, "a warning notification must be painted"
    severity, message = notifications[-1]
    assert severity == "warning", f"latest notification: {notifications[-1]!r}"
    assert message == _WRITE_FAIL_WARNING, (
        f"the latest painted warning must be exactly {_WRITE_FAIL_WARNING!r}; "
        f"got {message!r} (all notifications: {notifications!r})"
    )


# ---------------------------------------------------------------------------
# TC-B102-07 — total paste failure selects the current field text and
# paints the exact read warning.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["input", "textarea"], ids=["input", "textarea"])
def test_tc_b102_07_total_paste_failure_selects_field_and_paints_exact_warning(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    """TC-B102-07 (R-B102-CLIP-006): OS read None + internal empty.

    The field text must stay put, become fully selected (so the stale
    value cannot ride an unnoticed compare) and the latest painted
    warning must be exactly
    ``Clipboard read failed — try Ctrl+Shift+V or type the path manually.``
    The Input arm pins the existing batch-67 contract; the TextArea arm
    is RED on the pre-increment tree (its override does not exist).
    """
    _patch_os_read(monkeypatch, None)
    notifications: list = []
    original = "OLD_TEXT_STAYS_PUT"

    async def _drive() -> tuple:
        app = _ClipboardHarness()
        app._clipboard = ""
        async with app.run_test() as pilot:
            _capture_notify(app, notifications)
            widget = _widget(app, kind)
            _set_content(widget, kind, original)
            await pilot.pause()
            await _invoke(widget, "action_paste")
            await pilot.pause()
            return _content(widget), widget.selected_text

    content, selected_text = asyncio.run(_drive())
    assert content == original, (
        f"a failed paste must not corrupt the field; got {content!r}"
    )
    assert selected_text == original, (
        f"on total failure the CURRENT field text must be fully selected; "
        f"selected_text={selected_text!r}"
    )
    assert notifications, "a warning notification must be painted"
    severity, message = notifications[-1]
    assert severity == "warning", f"latest notification: {notifications[-1]!r}"
    assert message == _READ_FAIL_WARNING, (
        f"the latest painted warning must be exactly {_READ_FAIL_WARNING!r}; "
        f"got {message!r} (all notifications: {notifications!r})"
    )


# ---------------------------------------------------------------------------
# TC-B102-08 — TextArea empty-selection cut keeps the line-cut behaviour
# while writing the replaced line text to OS + internal clipboards.
# ---------------------------------------------------------------------------


def test_tc_b102_08_empty_selection_cut_cuts_cursor_line_to_os_and_internal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TC-B102-08 (R-B102-CLIP-003): no-selection cut deletes the cursor line.

    The replaced line text (what ``_delete_cursor_line`` returns) must go
    to the OS clipboard and the internal mirror — never an empty string,
    never a no-op (the mutant control). RED on the pre-increment tree:
    the inherited sync cut never reaches the write seam, so nothing is
    recorded.
    """
    recorded = _recording_writer(monkeypatch, result=True)

    async def _drive() -> tuple:
        app = _ClipboardHarness()
        async with app.run_test() as pilot:
            ta = app.query_one("#ta", CappedTextArea)
            ta.text = "first\nline_to_cut\nthird"
            ta.selection = ((0, 0), (0, 0))
            ta.cursor_location = (1, 2)
            await pilot.pause()
            await _invoke(ta, "action_cut")
            await pilot.pause()
            return ta.text, app.clipboard

    text, internal = asyncio.run(_drive())
    assert "line_to_cut" not in text, (
        f"the cursor line must be removed from the document; got {text!r}"
    )
    assert text == "first\nthird", f"got {text!r}"
    assert recorded, (
        "a line cut must attempt the OS write — an empty-selection cut "
        "must not become a no-op"
    )
    payload = recorded[0]
    assert payload.rstrip("\r\n") == "line_to_cut", (
        f"the OS payload must be the replaced line text; got {payload!r}"
    )
    assert payload.strip(), "the OS payload must never be an empty string"
    assert internal == payload, (
        f"OS and internal clipboards must receive the same replaced line "
        f"text; OS={payload!r} internal={internal!r}"
    )
