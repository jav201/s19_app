from __future__ import annotations

import ast
import asyncio
import base64
import gc
import json
import logging
import os
import queue
import re
import shutil
import subprocess
import sys
import sysconfig
import threading
import time
import traceback
import xml.sax.saxutils
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual import events
from textual.app import App
from textual.widgets import DataTable, Input, TextArea

from s19_app.tui.app import S19TuiApp
from s19_app.tui import app as app_module
from s19_app.tui import capped_text_area as capped_module
from s19_app.tui import os_clipboard_input as clipboard_module
from tests.support.b103_clipboard import (
    arm_tick_lateness,
    install_log_capture,
    other_program_write,
    remove_log_capture,
    require_isolated_clipboard,
)
from tests.support.timing import report_margin, timing_bound


REPO_ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = REPO_ROOT / "examples" / "case_00_public"
CAP = 65_536
SEED_APP = "SEED-APP-1b"
SEED_OS = "SEED-OS-1b"
WRITE_FAIL = "Clipboard write failed — copied inside the app only."
WRITE_WARNING = "OS clipboard write failed; retained Textual internal clipboard only"
NUL_REFUSAL = "Clipboard copy refused — NUL cannot be represented in the Windows text clipboard."
NUL_WARNING = "OS clipboard copy refused; payload contains NUL"
NUL3 = "A\x00B"
P65536 = "x" * CAP
P65537 = "x" * (CAP + 1)
P70000 = "P" * 70_000
NUL_AFTER = P65536 + "\x00"
HOSTILE_NAME = "[red]\x1b\x07\x1b]52;c;U0VFRF9PU0M=\x07\nSUFFIX"
OSC52_RE = re.compile(rb"\x1b\]52;c;([A-Za-z0-9+/=]+)\x07")


def _j75210() -> str:
    prefix = '{"payload":"'
    suffix = '"}'
    body = ["a"] * (75_210 - len(prefix) - len(suffix))
    body[CAP - 1 - len(prefix)] = "K"
    body[CAP - len(prefix)] = "D"
    value = prefix + "".join(body) + suffix
    assert len(value) == 75_210
    assert value[CAP - 1] == "K"
    assert value[CAP] == "D"
    assert json.loads(value)["payload"][CAP - 1 - len(prefix)] == "K"
    return value


J75210 = _j75210()


async def _settle(pilot, count: int = 6) -> None:
    for _ in range(count):
        await pilot.pause()
    await asyncio.sleep(0.03)
    await pilot.pause()


async def _wait(pilot, predicate, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("fixture predicate not satisfied before timeout")
        await asyncio.sleep(0.02)
        await pilot.pause()


async def _wait_copy_tail(pilot, ledger) -> None:
    await _wait(pilot, lambda: bool(ledger.tail_done))
    await _settle(pilot, 2)


async def _load_example(app, pilot, tmp_path: Path, name: str) -> None:
    target = tmp_path / name
    if not target.exists():
        shutil.copyfile(EXAMPLES / name, target)
    if name.endswith(".a2l"):
        app.load_a2l_from_path(target)
        await _wait(pilot, lambda: bool(getattr(app, "current_a2l_data", None)))
    else:
        app.load_from_path(target)
        await _wait(pilot, lambda: app.current_file is not None)
    await _settle(pilot)


def _notice_rows(app) -> list[tuple[str, str, float]]:
    return [
        (str(n.message), str(n.severity), float(n.timeout))
        for n in list(app._notifications)
    ]


def _mouse(kind, widget, x: int, y: int, button: int = 3):
    return kind(widget, x, y, 0, 0, button, False, False, False, x, y, None)


async def _right_click(app, pilot, widget, offset: tuple[int, int] = (2, 0)) -> None:
    region = widget.region
    _require(region.width > 0 and region.height > 0, "right-click target has zero area")
    x = region.x + offset[0]
    y = region.y + offset[1]
    app.post_message(_mouse(events.MouseDown, widget, x, y))
    app.post_message(_mouse(events.MouseUp, widget, x, y))
    await _settle(pilot)


def _instrument(app, monkeypatch: pytest.MonkeyPatch, *, writer_result=None, writer_delay: float = 0.0):
    if sys.platform == "win32":
        _winci_ready_or_skip()
        other_program_write(SEED_OS)
        if writer_result is True:
            writer_result = None
    ledger = SimpleNamespace(
        counts=Counter(),
        base_payloads=[],
        override_payloads=[],
        tail_payloads=[],
        tail_done=[],
        writer_payloads=[],
        writer_done=[],
        writer_threads=[],
        helper_payloads=[],
        osc_payloads=[],
        osc_requests=[],
        processes=[],
        os_clipboard=SEED_OS,
        original_process=clipboard_module.subprocess.run,
    )
    original_base = App.copy_to_clipboard
    original_override = app.copy_to_clipboard
    original_tail = clipboard_module._mirror_and_write_os_clipboard
    original_writer = clipboard_module.write_os_clipboard
    original_helper = getattr(clipboard_module, "_copy_notice_text", None)

    def base_spy(app_self, text: str):
        ledger.counts["base"] += 1
        ledger.base_payloads.append(text)
        return original_base(app_self, text)

    def override_spy(text: str):
        ledger.counts["override"] += 1
        ledger.override_payloads.append(text)
        return original_override(text)

    async def tail_spy(app_self, text: str):
        ledger.counts["tail"] += 1
        ledger.tail_payloads.append(text)
        try:
            return await original_tail(app_self, text)
        finally:
            ledger.tail_done.append(text)

    def writer_spy(text: str, *args, **kwargs):
        ledger.counts["writer"] += 1
        ledger.writer_payloads.append(text)
        ledger.writer_threads.append(threading.get_ident())
        try:
            if writer_delay:
                time.sleep(writer_delay)
            if writer_result is None:
                return original_writer(text, *args, **kwargs)
            if writer_result:
                ledger.os_clipboard = text
            return bool(writer_result)
        finally:
            ledger.writer_done.append(text)

    def helper_spy(text: str) -> str:
        ledger.counts["helper"] += 1
        ledger.helper_payloads.append(text)
        return original_helper(text)

    def process_spy(argv, **kwargs):
        ledger.counts["process"] += 1
        ledger.processes.append((list(argv), dict(kwargs)))
        if sys.platform == "win32":
            return ledger.original_process(argv, **kwargs)
        raise AssertionError("clipboard subprocess forbidden by this recorder")

    monkeypatch.setattr(App, "copy_to_clipboard", base_spy)
    monkeypatch.setattr(app, "copy_to_clipboard", override_spy)
    monkeypatch.setattr(clipboard_module, "_mirror_and_write_os_clipboard", tail_spy)
    monkeypatch.setattr(app_module, "_mirror_and_write_os_clipboard", tail_spy, raising=False)
    monkeypatch.setattr(capped_module, "_mirror_and_write_os_clipboard", tail_spy, raising=False)
    monkeypatch.setattr(clipboard_module, "write_os_clipboard", writer_spy)
    if original_helper is not None:
        monkeypatch.setattr(clipboard_module, "_copy_notice_text", helper_spy)
    monkeypatch.setattr(clipboard_module.subprocess, "run", process_spy)

    original_write = app._driver.write

    def osc_spy(data) -> None:
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        for match in OSC52_RE.finditer(raw):
            ledger.osc_requests.append(match.group(0))
            ledger.osc_payloads.append(base64.b64decode(match.group(1)).decode("utf-8"))
        return original_write(data)

    monkeypatch.setattr(app._driver, "write", osc_spy)
    app._clipboard = SEED_APP
    app._notifications.clear()
    return ledger


def other_program_read() -> str:
    """Read the real Windows clipboard as Base64, preserving every CR/LF."""
    require_isolated_clipboard("windows")
    program = clipboard_module._system_powershell()
    if not program:
        pytest.skip("not_run: isolated WinCI has no system PowerShell")
    if not Path(program).is_absolute():
        raise AssertionError("separate clipboard reader requires absolute system PowerShell")
    result = subprocess.run(
        [
            program,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "$ErrorActionPreference='Stop';"
            "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
            "$text=[string](Get-Clipboard -Raw);"
            "[Console]::Out.Write([Convert]::ToBase64String("
            "[System.Text.Encoding]::UTF8.GetBytes($text)))",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=10.0,
        shell=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode or result.stderr:
        raise AssertionError(
            "separate clipboard read failed: "
            f"exit={result.returncode}, stderr_chars={len(result.stderr)}"
        )
    return base64.b64decode(
        "".join(result.stdout.split()), validate=True
    ).decode("utf-8")


def _read_os(ledger) -> str:
    if sys.platform != "win32":
        return ledger.os_clipboard
    current = clipboard_module.subprocess.run
    clipboard_module.subprocess.run = ledger.original_process
    try:
        return other_program_read()
    finally:
        clipboard_module.subprocess.run = current


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _observe(app, ledger, **extra) -> dict:
    result = {
        "counts": {key: ledger.counts.get(key, 0) for key in (
            "override", "tail", "base", "writer", "helper", "process"
        )},
        "app": app.clipboard,
        "os": _read_os(ledger),
        "base_payloads": list(ledger.base_payloads),
        "override_payloads": list(ledger.override_payloads),
        "tail_payloads": list(ledger.tail_payloads),
        "writer_payloads": list(ledger.writer_payloads),
        "writer_threads": list(ledger.writer_threads),
        "helper_payloads": list(ledger.helper_payloads),
        "osc": list(ledger.osc_payloads),
        "osc_requests": list(ledger.osc_requests),
        "processes": list(ledger.processes),
        "notices": _notice_rows(app),
    }
    if hasattr(ledger, "while_open_os"):
        _require(ledger.while_open_os == SEED_OS, "clipboard changed while the fallback was open")
        result["while_open_os"] = ledger.while_open_os
    result.update(extra)
    return result


def _counts(obs: dict, *, override: int, tail: int, base: int, writer: int, osc: int, helper: int | None = None) -> None:
    actual = obs["counts"]
    expected = {"override": override, "tail": tail, "base": base, "writer": writer}
    for key, value in expected.items():
        _require(actual[key] == value, f"unexpected {key} call count")
    _require(len(obs["osc"]) == osc, "unexpected OSC payload count")
    _require(len(obs["osc_requests"]) == osc, "unexpected OSC request count")
    if helper is not None:
        _require(actual["helper"] == helper, "unexpected notice-helper call count")


def _success(obs: dict, original: str, notice: str, *, view: bool) -> None:
    capped = original[:CAP]
    _counts(
        obs,
        override=1 if view else 0,
        tail=1,
        base=1,
        writer=1,
        osc=1,
        helper=1,
    )
    _require(obs["override_payloads"] == ([original] if view else []), "override payload sequence differed")
    _require(obs["tail_payloads"] == [original], "tail did not receive the original text")
    _require(obs["base_payloads"] == [capped], "base did not receive exactly the capped text")
    _require(obs["writer_payloads"] == [capped], "writer did not receive exactly the capped text")
    _require(obs["helper_payloads"] == [original], "notice helper did not receive the original text")
    _require(obs["app"] == capped, "application clipboard payload differed")
    _require(obs["os"] == capped, "OS clipboard payload differed")
    _require(obs["osc"] == [capped], "OSC payload sequence differed")
    copied = [row for row in obs["notices"] if row[0].startswith("Copied")]
    _require(
        [(row[0], row[1]) for row in copied] == [(notice, "information")],
        "success notice sequence differed",
    )


def _failure(obs: dict, original: str, *, view: bool) -> None:
    _counts(obs, override=1 if view else 0, tail=1, base=1, writer=1, osc=1)
    _require(obs["app"] == original[:CAP], "application clipboard payload differed after failure")
    _require(obs["osc"] == [original[:CAP]], "OSC payload differed after failure")
    _require(obs["os"] == SEED_OS, "OS clipboard changed after a failed write")
    _require(
        not [row for row in obs["notices"] if row[0].startswith("Copied")],
        "failed write emitted a success notice",
    )
    warnings = [row for row in obs["notices"] if row[0] == WRITE_FAIL]
    _require(warnings == [(WRITE_FAIL, "warning", 6.0)], "write-failure notice sequence differed")


def _refusal(obs: dict, *, view: bool) -> None:
    _counts(obs, override=1 if view else 0, tail=1, base=0, writer=0, osc=0, helper=0)
    _require(obs["counts"]["process"] == 0, "NUL refusal started a clipboard process")
    _require(obs["app"] == SEED_APP, "NUL refusal changed the application clipboard")
    _require(obs["os"] == SEED_OS, "NUL refusal changed the OS clipboard")
    _require(obs["helper_payloads"] == [], "NUL refusal called the notice helper")
    _require(obs["notices"] == [(NUL_REFUSAL, "warning", 6.0)], "NUL refusal notice sequence differed")


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


def _no_secret(records: list, secret: str) -> None:
    """Reject direct, repr, escaped and XML-derived disclosure forms."""
    messages = [row[2] for row in records]
    needles = set(_disclosure_forms(secret).values())
    leaked = any(
        needle and needle in message for needle in needles for message in messages
    )
    _require(not leaked, "copied text or a derived prefix appeared in captured logs")


def _run_arms(monkeypatch: pytest.MonkeyPatch, arms) -> None:
    failures = []
    for label, arm in arms:
        try:
            arm()
        except AssertionError:
            failures.append(label)
        finally:
            monkeypatch.undo()
    _require(not failures, "clipboard arm failures: " + ", ".join(failures))


async def _select_hex(app, pilot, tmp_path: Path) -> str:
    await _load_example(app, pilot, tmp_path, "prg.s19")
    app.action_show_screen("workspace")
    await _settle(pilot)
    app.screen.clear_selection()
    await pilot.mouse_down("#hex_view", offset=(2, 1))
    await pilot.hover("#hex_view", offset=(40, 3))
    await pilot.mouse_up("#hex_view", offset=(40, 3))
    await _settle(pilot)
    selected = app.screen.get_selected_text()
    _require(bool(selected) and selected.count("\n") == 2, "hex selection did not contain exactly three lines")
    _require(len(set(selected.splitlines())) == 3, "hex selection lines were not distinct")
    return selected


async def _select_stats(app, pilot, tmp_path: Path) -> str:
    await _load_example(app, pilot, tmp_path, "prg.s19")
    app.action_show_screen("workspace")
    await _settle(pilot)
    app.screen.clear_selection()
    widget = app.query_one("#ws_stats")
    end = (max(1, widget.region.width - 1), 4)
    await pilot.mouse_down(widget, offset=(0, 0))
    await pilot.hover(widget, offset=end)
    await pilot.mouse_up(widget, offset=end)
    await _settle(pilot)
    selected = app.screen.get_selected_text()
    line_count = selected.count("\n") + 1 - int(selected.endswith("\n")) if selected else 0
    _require(line_count == 5, "stats selection did not contain exactly five lines")
    return selected


async def _show_json(app, pilot, text: str):
    app.action_show_screen("patch")
    await _settle(pilot)
    await pilot.click("#patch_tab_json")
    await _settle(pilot)
    widget = app.query_one("#patch_json_view", TextArea)
    widget.text = text
    widget.focus()
    await _settle(pilot)
    await pilot.press("f7")
    await _settle(pilot)
    assert widget.selected_text == text, (len(widget.selected_text), len(text))
    return widget


async def _show_box(app, pilot, kind: str, text: str, *, select: bool = True):
    if kind == "input":
        app.action_show_screen("a2l")
        await _settle(pilot)
        widget = app.query_one("#a2l_tags_filter_input", Input)
        widget.value = text
        if select:
            widget.selection = (0, len(text))
    else:
        app.action_show_screen("patch")
        await _settle(pilot)
        await pilot.click("#patch_tab_json")
        await _settle(pilot)
        widget = app.query_one("#patch_paste_text", TextArea)
        widget.text = text
        if select:
            widget.select_all()
    widget.focus()
    await _settle(pilot)
    return widget


async def _show_model_row(app, pilot, name: str):
    app.action_show_screen("a2l")
    await _settle(pilot)
    table = app.query_one("#a2l_tags_list", DataTable)
    table.clear(columns=True)
    table.add_columns("Row", "Type", "Tag")
    table.add_row("0", "SCALAR", "PAINTED-PROJECTION", key="a2l:0")
    app._a2l_row_key_to_tag = {"a2l:0": {"name": name}}
    await _settle(pilot)
    return table


async def _a2l_third_row(app, pilot, tmp_path: Path):
    await _load_example(app, pilot, tmp_path, "ASAP2_Demo_V171.a2l")
    app.action_show_screen("a2l")
    await _settle(pilot)
    table = app.query_one("#a2l_tags_list", DataTable)
    assert table.row_count >= 3
    key = app._a2l_row_key_to_tag["a2l:2"]
    expected = key["name"]
    assert expected == "ASAM.M.SCALAR.UBYTE.RAT_FUNC.IDENT.STATUS_STRING"
    painted = str(table.get_row_at(2)[0])
    assert expected not in painted or painted != expected
    return table, expected


def _view_observation(
    tmp_path: Path,
    monkeypatch,
    source: str,
    gesture: str,
    *,
    text: str | None = None,
    writer_result=True,
    held: bool = False,
) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            if source == "hex":
                expected = await _select_hex(app, pilot, tmp_path)
                widget = app.query_one("#hex_view")
                right_offset = (10, 2)
            elif source == "stats":
                expected = await _select_stats(app, pilot, tmp_path)
                widget = app.query_one("#ws_stats")
                right_offset = (2, 1)
            elif source == "json":
                assert text is not None
                expected = text
                widget = await _show_json(app, pilot, text)
                right_offset = (2, 0)
            else:
                raise AssertionError(source)
            ledger = _instrument(app, monkeypatch, writer_result=writer_result)
            held_state = _hold_clipboard() if held and sys.platform == "win32" else None
            try:
                if gesture == "key":
                    await pilot.press("ctrl+c")
                    await _settle(pilot)
                else:
                    await _right_click(app, pilot, widget, right_offset)
                await _wait_copy_tail(pilot, ledger)
            finally:
                if held_state is not None:
                    _release_clipboard(held_state)
            return _observe(app, ledger, expected=expected)

    return asyncio.run(drive())


def _box_observation(tmp_path: Path, monkeypatch, kind: str, action: str, text: str, *, writer_result=True) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            widget = await _show_box(app, pilot, kind, text)
            ledger = _instrument(app, monkeypatch, writer_result=writer_result)
            before_text = widget.value if kind == "input" else widget.text
            before_selection = widget.selection
            if action == "right":
                await _right_click(app, pilot, widget)
            else:
                await pilot.press("ctrl+c" if action == "copy" else "ctrl+x")
                await _settle(pilot)
            await _wait_copy_tail(pilot, ledger)
            after_text = widget.value if kind == "input" else widget.text
            return _observe(
                app,
                ledger,
                expected=text,
                before_text=before_text,
                before_selection=before_selection,
                after_text=after_text,
                after_selection=widget.selection,
            )

    return asyncio.run(drive())


def _row_observation(
    tmp_path: Path,
    monkeypatch,
    name: str | None = None,
    *,
    writer_result=True,
    held: bool = False,
) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            if name is None:
                table, expected = await _a2l_third_row(app, pilot, tmp_path)
                row = 2
            else:
                table = await _show_model_row(app, pilot, name)
                expected = app._a2l_row_key_to_tag["a2l:0"]["name"]
                row = 0
            ledger = _instrument(app, monkeypatch, writer_result=writer_result)
            held_state = _hold_clipboard() if held and sys.platform == "win32" else None
            try:
                await _right_click(app, pilot, table, (4, table.header_height + row))
                await _wait_copy_tail(pilot, ledger)
            finally:
                if held_state is not None:
                    _release_clipboard(held_state)
            return _observe(app, ledger, expected=expected)

    return asyncio.run(drive())


def _injected_hex_key_observation(tmp_path: Path, monkeypatch, text: str) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            app.action_show_screen("workspace")
            await _settle(pilot)
            owner = app.query_one("#hex_scroll")
            owner.focus()
            await _settle(pilot)
            monkeypatch.setattr(app.screen, "get_selected_text", lambda: text)
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+c")
            await _wait_copy_tail(pilot, ledger)
            return _observe(app, ledger, expected=text)

    return asyncio.run(drive())


def test_r_copy_06_1_button_keeps_seeds(tmp_path, monkeypatch) -> None:
    """R-COPY.6/1: button focus, while the fallback is open and after n."""
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            app.query_one("#search_button").focus()
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+c")
            await _settle(pilot)
            while_open = app.clipboard
            ledger.while_open_os = _read_os(ledger)
            await pilot.press("n")
            await _settle(pilot)
            return while_open, app.clipboard, _observe(app, ledger)
    while_open, after_n, obs = asyncio.run(drive())
    _require(while_open == after_n == obs["app"] == SEED_APP, "copy changed the application clipboard seed")
    _require(obs["os"] == SEED_OS, "OS clipboard seed changed")
    _counts(obs, override=0, tail=0, base=0, writer=0, osc=0)


def test_r_copy_06_2_no_focus_keeps_seeds(tmp_path, monkeypatch) -> None:
    """R-COPY.6/2: no focused widget."""
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            app.screen.set_focus(None)
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+c")
            await _settle(pilot)
            while_open = app.clipboard
            ledger.while_open_os = _read_os(ledger)
            await pilot.press("n")
            await _settle(pilot)
            return while_open, _observe(app, ledger)
    while_open, obs = asyncio.run(drive())
    _require(while_open == obs["app"] == SEED_APP, "copy changed the application clipboard seed")
    _require(obs["os"] == SEED_OS, "OS clipboard seed changed")
    _counts(obs, override=0, tail=0, base=0, writer=0, osc=0)


def test_r_copy_06_3_highlighted_row_is_not_a_selection(tmp_path, monkeypatch) -> None:
    """R-COPY.6/3: a highlighted table row is not copied by Ctrl+C."""
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            await _a2l_third_row(app, pilot, tmp_path)
            table = app.query_one("#a2l_tags_list", DataTable)
            table.focus()
            table.move_cursor(row=2)
            await _settle(pilot)
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+c")
            await _settle(pilot)
            while_open = app.clipboard
            ledger.while_open_os = _read_os(ledger)
            await pilot.press("n")
            await _settle(pilot)
            return while_open, _observe(app, ledger)
    while_open, obs = asyncio.run(drive())
    _require(while_open == obs["app"] == SEED_APP, "copy changed the application clipboard seed")
    _require(obs["os"] == SEED_OS, "OS clipboard seed changed")
    _counts(obs, override=0, tail=0, base=0, writer=0, osc=0)


def test_r_copy_06_4_empty_input_keeps_seeds(tmp_path, monkeypatch) -> None:
    """R-COPY.6/4: empty single-line box, checks before and after n."""
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            widget = await _show_box(app, pilot, "input", "", select=False)
            assert widget.value == ""
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+c")
            await _settle(pilot)
            while_open = app.clipboard
            ledger.while_open_os = _read_os(ledger)
            await pilot.press("n")
            await _settle(pilot)
            return while_open, _observe(app, ledger)
    while_open, obs = asyncio.run(drive())
    _require(while_open == obs["app"] == SEED_APP, "copy changed the application clipboard seed")
    _require(obs["os"] == SEED_OS, "OS clipboard seed changed")
    _counts(obs, override=0, tail=0, base=0, writer=0, osc=0)


def test_r_copy_06_5_empty_json_selection_keeps_seeds(tmp_path, monkeypatch) -> None:
    """R-COPY.6/5: stock JSON view with no selection."""
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            app.action_show_screen("patch")
            await _settle(pilot)
            await pilot.click("#patch_tab_json")
            widget = app.query_one("#patch_json_view", TextArea)
            widget.focus()
            widget.selection = ((0, 0), (0, 0))
            await _settle(pilot)
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+c")
            await _settle(pilot)
            while_open = app.clipboard
            ledger.while_open_os = _read_os(ledger)
            await pilot.press("n")
            await _settle(pilot)
            return while_open, _observe(app, ledger)
    while_open, obs = asyncio.run(drive())
    _require(while_open == obs["app"] == SEED_APP, "copy changed the application clipboard seed")
    _require(obs["os"] == SEED_OS, "OS clipboard seed changed")
    _counts(obs, override=0, tail=0, base=0, writer=0, osc=0)


def test_r_copy_07_1_row_notice_once(tmp_path, monkeypatch) -> None:
    """R-COPY.7/1: one singular information notice after a row copy."""
    obs = _row_observation(tmp_path, monkeypatch)
    _success(obs, obs["expected"], "Copied 1 line to the clipboard.", view=True)


def test_r_copy_07_2_stats_right_click_notice(tmp_path, monkeypatch) -> None:
    """R-COPY.7/2: five selected stats lines produce one notice."""
    obs = _view_observation(tmp_path, monkeypatch, "stats", "right")
    _success(obs, obs["expected"], "Copied 5 lines to the clipboard.", view=True)


def test_r_copy_07_3_hex_key_notice(tmp_path, monkeypatch) -> None:
    """R-COPY.7/3: three selected hex lines produce one notice."""
    obs = _view_observation(tmp_path, monkeypatch, "hex", "key")
    _success(obs, obs["expected"], "Copied 3 lines to the clipboard.", view=True)


def test_r_copy_07_4_direct_input_copy_notice(tmp_path, monkeypatch) -> None:
    """R-COPY.7/4: direct OsClipboardInput copy, not the view override."""
    obs = _box_observation(tmp_path, monkeypatch, "input", "copy", "abc")
    _success(obs, "abc", "Copied 1 line to the clipboard.", view=False)
    _require(obs["after_text"] == obs["before_text"] == "abc", "direct input copy changed its text")
    _require(obs["after_selection"] == obs["before_selection"], "direct input copy changed its selection")


def test_r_copy_07_5_direct_textarea_copy_and_final_lf(tmp_path, monkeypatch) -> None:
    """R-COPY.7/5: three lines, with or without a final LF."""
    def arm(text):
        def check():
            obs = _box_observation(tmp_path, monkeypatch, "textarea", "copy", text)
            _success(obs, text, "Copied 3 lines to the clipboard.", view=False)
            _require(obs["after_text"] == text, "direct textarea copy changed its text")
        return check
    _run_arms(monkeypatch, [
        ("no-final-lf", arm("L1\nL2\nL3")),
        ("final-lf", arm("L1\nL2\nL3\n")),
    ])


def test_r_copy_07_6_direct_cut_notices_and_cap(tmp_path, monkeypatch) -> None:
    """R-COPY.7/6: direct cuts in both classes, including line cut and cap."""
    def cut(kind, text, notice):
        def check():
            obs = _box_observation(tmp_path, monkeypatch, kind, "cut", text)
            _success(obs, text, notice, view=False)
            _require(obs["after_text"] == "", "direct cut did not empty its box")
        return check
    def line_cut():
        obs = _line_cut_observation(tmp_path, monkeypatch)
        _counts(obs, override=0, tail=1, base=1, writer=1, osc=1, helper=1)
        payloads = obs["tail_payloads"] + obs["base_payloads"] + obs["writer_payloads"] + obs["osc"] + [obs["app"], obs["os"]]
        _require(all(payload in {"line_to_cut", "line_to_cut\n"} for payload in payloads), "line-cut payload escaped its exact alternatives")
        _require(len({payload for payload in payloads}) == 1, "line-cut sinks disagreed on the payload")
        _require(obs["helper_payloads"] == payloads[:1], "line-cut notice-helper payload differed")
        _require([(row[0], row[1]) for row in obs["notices"] if row[0].startswith("Copied")] == [
            ("Copied 1 line to the clipboard.", "information")
        ], "line-cut success notice sequence differed")
        _require(obs["after_text"] == "first\nthird", "line cut left unexpected box text")
    _run_arms(monkeypatch, [
        ("input", cut("input", "abc", "Copied 1 line to the clipboard.")),
        ("textarea", cut("textarea", "L1\nL2\nL3", "Copied 3 lines to the clipboard.")),
        ("textarea-line-cut", line_cut),
        ("input-over-cap", cut("input", P70000, "Copied the first 65,536 characters to the clipboard (70,000 in all).")),
        ("textarea-over-cap", cut("textarea", P70000, "Copied the first 65,536 characters to the clipboard (70,000 in all).")),
    ])


def test_r_copy_07_7_direct_right_click_notice_once(tmp_path, monkeypatch) -> None:
    """R-COPY.7/7: direct right-click and E3A-24(c) exclusion."""
    def arm(kind, text, notice):
        def check():
            obs = _box_observation(tmp_path, monkeypatch, kind, "right", text)
            _success(obs, text, notice, view=False)
            _require(obs["after_text"] == text, "direct right-click copy changed its text")
        return check
    def unrelated_view():
        obs = _unrelated_view_box_observation(tmp_path, monkeypatch)
        _success(obs, "abc", "Copied 1 line to the clipboard.", view=False)
        _require(obs["after_text"] == "abc", "unrelated-view copy changed its box text")
        _require(obs["unrelated"] not in obs["app"], "unrelated view text reached the application clipboard")
        _require(all(obs["unrelated"] not in payload for payload in obs["osc"] + obs["writer_payloads"]), "unrelated view text reached a copy sink")
    _run_arms(monkeypatch, [
        ("input", arm("input", "abc", "Copied 1 line to the clipboard.")),
        ("textarea", arm("textarea", "L1\nL2\nL3", "Copied 3 lines to the clipboard.")),
        ("e3a-24c-unrelated-view", unrelated_view),
    ])


def test_r_copy_07_8_failed_write_has_no_success_notice(tmp_path, monkeypatch) -> None:
    """R-COPY.7/8: writer failure yields only the existing warning."""
    if sys.platform == "win32":
        pytest.skip("Linux failing-writer arm; WinCI uses the isolated held clipboard")
    obs = _row_observation(tmp_path, monkeypatch, writer_result=None)
    _failure(obs, obs["expected"], view=True)


def test_r_copy_08_1_key_caps_json_and_direct_boxes(tmp_path, monkeypatch) -> None:
    """R-COPY.8/1 plus R-PASTE.12/1 regression: cap before every sink."""
    def json_arm():
        obs = _view_observation(tmp_path, monkeypatch, "json", "key", text=J75210)
        _success(obs, J75210, "Copied the first 65,536 characters to the clipboard (75,210 in all).", view=True)
    def box_arm(kind):
        def check():
            obs = _box_observation(tmp_path, monkeypatch, kind, "copy", P70000)
            _success(obs, P70000, "Copied the first 65,536 characters to the clipboard (70,000 in all).", view=False)
        return check
    _run_arms(monkeypatch, [
        ("json-key", json_arm),
        ("input-key", box_arm("input")),
        ("textarea-key", box_arm("textarea")),
    ])


def test_r_copy_08_2_right_click_caps_json_and_direct_boxes(tmp_path, monkeypatch) -> None:
    """R-COPY.8/2 plus R-PASTE.12/3: right-click cap on all three sources."""
    def json_arm():
        obs = _view_observation(tmp_path, monkeypatch, "json", "right", text=J75210)
        _success(obs, J75210, "Copied the first 65,536 characters to the clipboard (75,210 in all).", view=True)
    def box_arm(kind):
        def check():
            obs = _box_observation(tmp_path, monkeypatch, kind, "right", P70000)
            _success(obs, P70000, "Copied the first 65,536 characters to the clipboard (70,000 in all).", view=False)
        return check
    _run_arms(monkeypatch, [
        ("json-right", json_arm),
        ("input-right", box_arm("input")),
        ("textarea-right", box_arm("textarea")),
    ])


def test_r_copy_09_1_cut_notice_original_n_and_boundaries(tmp_path, monkeypatch) -> None:
    """R-COPY.9/1: original N, exact cap boundary, and no cut on failure."""
    def over_cap():
        obs = _view_observation(tmp_path, monkeypatch, "json", "key", text=J75210)
        _success(obs, J75210, "Copied the first 65,536 characters to the clipboard (75,210 in all).", view=True)
    def exact_cap():
        obs = _box_observation(tmp_path, monkeypatch, "input", "copy", P65536)
        _success(obs, P65536, "Copied 1 line to the clipboard.", view=False)
    def one_over():
        obs = _box_observation(tmp_path, monkeypatch, "input", "copy", P65537)
        _success(obs, P65537, "Copied the first 65,536 characters to the clipboard (65,537 in all).", view=False)
    def failure():
        obs = _view_observation(
            tmp_path,
            monkeypatch,
            "json",
            "key",
            text=J75210,
            writer_result=None,
            held=True,
        )
        _failure(obs, J75210, view=True)
    _run_arms(monkeypatch, [
        ("original-75210", over_cap),
        ("exact-65536", exact_cap),
        ("after-65537", one_over),
        ("failed-over-cap-write", failure),
    ])


def test_r_copy_09_2_right_click_cut_notice_original_n(tmp_path, monkeypatch) -> None:
    """R-COPY.9/2: right-click uses original N, never the capped length."""
    obs = _view_observation(tmp_path, monkeypatch, "json", "right", text=J75210)
    _success(obs, J75210, "Copied the first 65,536 characters to the clipboard (75,210 in all).", view=True)


def _with_logs(observe):
    logger = logging.getLogger("s19_app")
    previous_level = logger.level
    logger.setLevel(logging.DEBUG)
    records = install_log_capture()
    try:
        obs = observe()
    finally:
        remove_log_capture(records)
        logger.setLevel(previous_level)
    return obs, records


def _assert_nul_log(records: list, payload: str) -> None:
    warnings = [message for _, level, message in records if level == "WARNING"]
    _require(warnings == [NUL_WARNING], "NUL warning sequence differed")
    _no_secret(records, payload)


def test_r_copy_25_1_view_and_row_nul_fail_closed(tmp_path, monkeypatch) -> None:
    """R-COPY.25/1: view key/right-click and raw A2L name refuse capped NUL."""
    def view_key():
        obs, records = _with_logs(lambda: _injected_hex_key_observation(tmp_path, monkeypatch, NUL3))
        _refusal(obs, view=True)
        _assert_nul_log(records, NUL3)
    def view_right():
        obs, records = _with_logs(lambda: _view_observation(tmp_path, monkeypatch, "json", "right", text=NUL3))
        _refusal(obs, view=True)
        _assert_nul_log(records, NUL3)
    def row_right():
        payload = "VISIBLE\x00SECRET-SUFFIX"
        obs, records = _with_logs(lambda: _row_observation(tmp_path, monkeypatch, payload))
        _refusal(obs, view=True)
        _assert_nul_log(records, payload)
    _run_arms(monkeypatch, [
        ("view-key", view_key),
        ("view-right-click", view_right),
        ("a2l-full-name-right-click", row_right),
    ])


def test_r_copy_25_2_every_direct_box_route_nul_fail_closed(tmp_path, monkeypatch) -> None:
    """R-COPY.25/2: both box classes × copy/cut/right-click refuse before sinks."""
    def arm(kind, action):
        def check():
            obs, records = _with_logs(lambda: _box_observation(tmp_path, monkeypatch, kind, action, NUL3))
            _refusal(obs, view=False)
            _assert_nul_log(records, NUL3)
            if action == "cut":
                _require(obs["after_text"] == "", "refusal must not restore the local cut")
            else:
                _require(obs["after_text"] == NUL3, "non-cut refusal changed its box text")
                _require(obs["after_selection"] == obs["before_selection"], "non-cut refusal changed its selection")
        return check
    _run_arms(monkeypatch, [
        (f"{kind}-{action}", arm(kind, action))
        for kind in ("input", "textarea")
        for action in ("copy", "cut", "right")
    ])


def test_r_copy_25_3_nul_only_after_cap_is_allowed(tmp_path, monkeypatch) -> None:
    """R-COPY.25/3: character 65,537 is discarded; original N is retained."""
    assert len(NUL_AFTER) == 65_537
    assert NUL_AFTER[:CAP] == P65536
    assert NUL_AFTER.count("\x00") == 1 and NUL_AFTER[CAP] == "\x00"
    notice = "Copied the first 65,536 characters to the clipboard (65,537 in all)."
    def view_key():
        obs, records = _with_logs(lambda: _view_observation(tmp_path, monkeypatch, "json", "key", text=NUL_AFTER))
        _success(obs, NUL_AFTER, notice, view=True)
        _require(NUL_WARNING not in [row[2] for row in records], "post-cap NUL emitted a refusal warning")
        _require(NUL_REFUSAL not in [row[0] for row in obs["notices"]], "post-cap NUL emitted a refusal notice")
    def box(kind):
        def check():
            obs, records = _with_logs(lambda: _box_observation(tmp_path, monkeypatch, kind, "copy", NUL_AFTER))
            _success(obs, NUL_AFTER, notice, view=False)
            _require(NUL_WARNING not in [row[2] for row in records], "post-cap NUL emitted a refusal warning")
            _require(NUL_REFUSAL not in [row[0] for row in obs["notices"]], "post-cap NUL emitted a refusal notice")
        return check
    _run_arms(monkeypatch, [
        ("view-key", view_key),
        ("input-copy", box("input")),
        ("textarea-copy", box("textarea")),
    ])


def test_r_paste_09_101_view_key_failure_warning(tmp_path, monkeypatch) -> None:
    """R-PASTE.9/101: view-key failure warning, one six-second warning."""
    if sys.platform == "win32":
        pytest.skip("Linux failing-writer arm")
    obs = _view_observation(tmp_path, monkeypatch, "hex", "key", writer_result=None)
    _failure(obs, obs["expected"], view=True)


def test_r_paste_09_102_view_right_failure_warning(tmp_path, monkeypatch) -> None:
    """R-PASTE.9/102: view-right-click failure warning."""
    if sys.platform == "win32":
        pytest.skip("Linux failing-writer arm")
    obs = _view_observation(tmp_path, monkeypatch, "hex", "right", writer_result=None)
    _failure(obs, obs["expected"], view=True)


def test_r_paste_09_103_row_right_failure_warning(tmp_path, monkeypatch) -> None:
    """R-PASTE.9/103: row-right-click failure warning."""
    if sys.platform == "win32":
        pytest.skip("Linux failing-writer arm")
    obs = _row_observation(tmp_path, monkeypatch, writer_result=None)
    _failure(obs, obs["expected"], view=True)


def test_r_paste_10_101_exact_tail_warning_without_payload(tmp_path, monkeypatch) -> None:
    """R-PASTE.10/101: exact tail WARNING survives the writer cascade log."""
    if sys.platform == "win32":
        pytest.skip("Linux failing-writer arm")
    secret = "SECRET-COPY-43"
    obs, records = _with_logs(lambda: _row_observation(tmp_path, monkeypatch, secret, writer_result=None))
    _failure(obs, secret, view=True)
    warnings = [message for _, level, message in records if level == "WARNING"]
    _require(WRITE_WARNING in warnings, "exact tail write warning is missing")
    _require(any(message.startswith("write_os_clipboard: every strategy failed") for message in warnings), "writer cascade warning is missing")
    _no_secret(records, secret)


def test_r_tui_043_13_101_no_copied_text_or_prefix_in_logs(tmp_path, monkeypatch) -> None:
    """R-TUI-043.13/101: key/right/row/failure routes never log copied text."""
    winci = sys.platform == "win32"

    def view(gesture):
        def check():
            obs, records = _with_logs(lambda: _view_observation(tmp_path, monkeypatch, "hex", gesture, writer_result=None))
            if winci:
                _success(obs, obs["expected"], "Copied 3 lines to the clipboard.", view=True)
            else:
                _failure(obs, obs["expected"], view=True)
            _no_secret(records, obs["expected"])
        return check

    def row(writer_result, *, held=False):
        def check():
            secret = "SECRET-COPY-43"
            obs, records = _with_logs(lambda: _row_observation(
                tmp_path, monkeypatch, secret, writer_result=writer_result, held=held,
            ))
            if held or not writer_result:
                _failure(obs, secret, view=True)
            else:
                _success(obs, secret, "Copied 1 line to the clipboard.", view=True)
            _no_secret(records, secret)
        return check

    def xml_known_bad() -> None:
        secret = "<&>\"'\r\n\tSECRET-COPY-43"
        forms = _disclosure_forms(secret)
        plain_needles = [
            value for name, value in forms.items() if not name.startswith("xml")
        ]
        for name, needle in forms.items():
            if not name.startswith("xml"):
                continue
            _require(
                not any(plain and plain in needle for plain in plain_needles),
                f"XML known-bad {name} is also matched by a plain disclosure form",
            )
            try:
                _no_secret([("known-bad", "ERROR", needle)], secret)
            except AssertionError:
                pass
            else:
                raise AssertionError(f"XML disclosure form was not rejected: {name}")

    if winci:
        arms = [
            ("view-key-real-writer", view("key")),
            ("view-right-click-real-writer", view("right")),
            ("row-success-real-writer", row(True)),
            ("row-held-real-writer", row(None, held=True)),
        ]
    else:
        arms = [
            ("view-key", view("key")),
            ("view-right-click", view("right")),
            ("row-success-recorder", row(True)),
            ("row-existing-failing-writer", row(None)),
        ]
    arms.append(("xml-derived-log-forms-known-bad", xml_known_bad))
    _run_arms(monkeypatch, arms)


def _powershell_transport_observation(tmp_path: Path, monkeypatch, payload: str) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            table = await _show_model_row(app, pilot, payload)
            real_writer = clipboard_module.write_os_clipboard
            ledger = _instrument(app, monkeypatch, writer_result=True)
            winci = sys.platform == "win32"

            if winci:
                instrumented_writer = clipboard_module.write_os_clipboard

                def powershell_writer(text: str):
                    return instrumented_writer(
                        text,
                        strategies=(("powershell", clipboard_module._write_via_powershell),),
                    )

                transport = "winci-real-powershell"
            else:
                def fake_run(argv, **kwargs):
                    ledger.counts["process"] += 1
                    ledger.processes.append((list(argv), dict(kwargs)))
                    return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

                def powershell_writer(text: str):
                    ledger.counts["writer"] += 1
                    ledger.writer_payloads.append(text)
                    ledger.writer_threads.append(threading.get_ident())
                    written = real_writer(
                        text,
                        strategies=(("powershell", clipboard_module._write_via_powershell),),
                    )
                    if written:
                        ledger.os_clipboard = text
                    return written

                transport = "linux-simulated-powershell"
                monkeypatch.setattr(clipboard_module, "sys", SimpleNamespace(platform="win32"))
                monkeypatch.setattr(clipboard_module, "_system_powershell", lambda: "/usr/bin/pwsh")
                monkeypatch.setattr(clipboard_module, "_system_directory", lambda: "/usr/bin")
                monkeypatch.setattr(clipboard_module.subprocess, "run", fake_run)

            monkeypatch.setattr(clipboard_module, "write_os_clipboard", powershell_writer)
            await _right_click(app, pilot, table, (4, table.header_height))
            await _wait_copy_tail(pilot, ledger)
            return _observe(app, ledger, expected=payload, transport=transport)

    return asyncio.run(drive())


def _hostile_powershell_observation(tmp_path: Path, monkeypatch) -> dict:
    return _powershell_transport_observation(tmp_path, monkeypatch, HOSTILE_NAME)


def _assert_no_clipboard_app_import() -> None:
    tree = ast.parse(Path(clipboard_module.__file__).read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            offenders.extend(alias.name for alias in node.names if alias.name == "s19_app.tui.app")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "s19_app.tui.app" or (node.level and node.module == "app"):
                offenders.append(node.module)
    assert offenders == [], offenders


def test_e5_powershell_preserves_lf_and_emits_bom_free_readers() -> None:
    """Static E5 oracle: binary CR/LF transport and BOM-free readers."""
    failures = []
    write_command = "".join(clipboard_module._POWERSHELL_WRITE_COMMAND)
    if "[Console]::In.ReadToEnd()" not in write_command:
        failures.append("writer must read stdin once with [Console]::In.ReadToEnd()")
    if "[Windows.Clipboard]::SetText($text)" not in write_command:
        failures.append("writer must call .NET [Windows.Clipboard]::SetText($text)")
    if "Set-Clipboard" in write_command:
        failures.append("writer must not rebuild lines with Set-Clipboard")

    utf8_without_bom = re.compile(
        r"UTF8Encoding\]?\s*(?:::\s*new\s*)?\(\s*\$false\s*\)"
    )
    readers = (
        (Path(clipboard_module.__file__), "_read_via_powershell"),
        (Path(__file__), "other_program_read"),
    )
    for path, function_name in readers:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        function = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        )
        literals = "".join(
            node.value
            for node in ast.walk(function)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
        output_encodings = re.findall(
            r"\[Console\]::OutputEncoding\s*=\s*([^;]+)", literals
        )
        if len(output_encodings) != 1 or not all(
            utf8_without_bom.search(encoding) for encoding in output_encodings
        ):
            failures.append(f"{function_name} must use UTF8Encoding($false) for stdout")

    product_tree = ast.parse(Path(clipboard_module.__file__).read_text(encoding="utf-8"))
    for function_name, required_method in (
        ("_read_via_powershell", "decode"),
        ("_write_via_powershell", "encode"),
    ):
        function = next(
            node
            for node in product_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == function_name
        )
        for node in ast.walk(function):
            if not isinstance(node, ast.Dict):
                continue
            keys = {
                key.value
                for key in node.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
            }
            forbidden = keys.intersection({"text", "encoding", "errors", "newline"})
            if forbidden:
                failures.append(
                    f"{function_name} must not pass text-mode subprocess keys: "
                    f"{sorted(forbidden)}"
                )
        methods = {
            node.func.attr
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        if required_method not in methods:
            failures.append(f"{function_name} must use explicit UTF-8 {required_method}")

    assert not failures, "\n".join(failures)


def test_r_tui_043_13_102_hostile_exact_payload_transport_and_logs(tmp_path, monkeypatch) -> None:
    """R-TUI-043.13/102: exact binary PowerShell transport and safe logs."""
    _assert_no_clipboard_app_import()
    _require(HOSTILE_NAME.count("\n") == 1, "hostile fixture must contain one internal LF")
    if "\x00" in HOSTILE_NAME:
        raise AssertionError("hostile fixture unexpectedly contains NUL")
    final_lf = HOSTILE_NAME + "\n"
    _require(final_lf.count("\n") == 2 and final_lf.endswith("\n"), "final-LF fixture is invalid")
    transport_payloads = (
        ("hostile-no-final-lf", HOSTILE_NAME),
        ("hostile-final-lf", final_lf),
        ("unicode", "SEED-Ω-漢字-🙂"),
        ("cr", "SEED-CR\rNEXT"),
        ("crlf", "SEED-CRLF\r\nNEXT"),
    )
    winci = sys.platform == "win32"

    def transport_arm(payload: str):
        def check() -> None:
            obs, records = _with_logs(
                lambda: _powershell_transport_observation(tmp_path, monkeypatch, payload)
            )
            expected_transport = "winci-real-powershell" if winci else "linux-simulated-powershell"
            _require(obs["transport"] == expected_transport, "unexpected PowerShell transport")
            try:
                _success(
                    obs,
                    payload,
                    clipboard_module._copy_notice_text(payload),
                    view=True,
                )
            except AssertionError:
                raise AssertionError("exact-payload success oracle failed") from None
            _require(obs["counts"]["process"] == 1, "unexpected PowerShell process count")
            _require(len(obs["processes"]) == 1, "unexpected PowerShell process ledger cardinality")
            argv, kwargs = obs["processes"][0]
            program = clipboard_module._system_powershell()
            _require(program is not None, "system PowerShell path is missing")
            expected_argv = [
                program,
                "-NonInteractive",
                *clipboard_module._POWERSHELL_WRITE_COMMAND,
            ]
            if argv != expected_argv:
                raise AssertionError("PowerShell argv did not match the static system command")
            if kwargs.get("shell") is not False:
                raise AssertionError("PowerShell must run with shell=False")
            if kwargs.get("cwd") != clipboard_module._system_directory():
                raise AssertionError("PowerShell cwd was not the system directory")
            expected_input = payload.encode("utf-8", errors="replace")
            if kwargs.get("input") != expected_input:
                raise AssertionError("PowerShell binary stdin payload differed")
            forbidden = {"text", "encoding", "errors", "newline"}.intersection(kwargs)
            if forbidden:
                raise AssertionError("PowerShell writer enabled text-mode transport")
            if winci and not (Path(program).is_absolute() and Path(program).is_file()):
                raise AssertionError("WinCI PowerShell path was not an absolute existing file")
            if any(payload in str(arg) or payload[:16] in str(arg) for arg in argv):
                raise AssertionError("copied text or its prefix appeared in PowerShell argv")
            if NUL_REFUSAL in [row[0] for row in obs["notices"]]:
                raise AssertionError("hostile payload unexpectedly triggered the NUL refusal")
            if NUL_WARNING in [row[2] for row in records]:
                raise AssertionError("hostile payload unexpectedly logged the NUL warning")
            _no_secret(records, payload)
        return check

    def forced_reader() -> None:
        attempts = []

        def ctypes_unavailable() -> None:
            attempts.append("ctypes-win32")
            return None

        strategies = (
            ("ctypes-win32", ctypes_unavailable),
            ("powershell", clipboard_module._read_via_powershell),
        )
        if not winci:
            outputs = iter(
                [
                    *(payload.encode("utf-8") for _, payload in transport_payloads),
                    b"",
                ]
            )
            started = []

            def fake_run(argv, **kwargs):
                started.append((list(argv), dict(kwargs)))
                return SimpleNamespace(returncode=0, stdout=next(outputs), stderr=b"")

            monkeypatch.setattr(clipboard_module, "sys", SimpleNamespace(platform="win32"))
            monkeypatch.setattr(clipboard_module, "_system_powershell", lambda: "/usr/bin/pwsh")
            monkeypatch.setattr(clipboard_module, "_system_directory", lambda: "/usr/bin")
            monkeypatch.setattr(clipboard_module.subprocess, "run", fake_run)
            for label, payload in transport_payloads:
                value = clipboard_module.read_os_clipboard(strategies=strategies)
                _require(value == payload, f"forced PowerShell read changed {label} payload")
            empty = clipboard_module.read_os_clipboard(strategies=strategies)
            _require(empty is None, "empty PowerShell stdout must answer None")
            expected_calls = len(transport_payloads) + 1
            _require(
                attempts == ["ctypes-win32"] * expected_calls,
                "forced reader did not retry every ctypes failure",
            )
            _require(
                len(started) == expected_calls,
                "forced reader did not start the expected PowerShell processes",
            )
            _require(
                all(call[1].get("shell") is False for call in started),
                "forced PowerShell reader must use shell=False",
            )
            _require(
                all(
                    not {"text", "encoding", "errors", "newline"}.intersection(call[1])
                    for call in started
                ),
                "forced PowerShell reader enabled text-mode transport",
            )
            return

        system_ps = clipboard_module._system_powershell()
        system_dir = clipboard_module._system_directory()
        _require(system_ps is not None and system_dir is not None, "system PowerShell is required")
        decoy_cwd = tmp_path / "tail-decoy-cwd"
        decoy_path = tmp_path / "tail-decoy-path"
        decoy_cwd.mkdir()
        decoy_path.mkdir()
        decoy_source = tmp_path / "tail-decoy.cs"
        decoy_source.write_text(
            "using System; using System.IO; internal static class Decoy { "
            "private static int Main() { "
            "var marker = Environment.GetEnvironmentVariable(\"B103_TAIL_DECOY_MARKER\"); "
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
        _require(compiler is not None, "absolute .NET Framework compiler not found for tail decoy")
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
        _require(compiled.returncode == 0, "tail decoy compilation failed")
        shutil.copyfile(decoy_in_path, decoy_cwd / "powershell.exe")
        marker = tmp_path / "tail-decoy-executed.marker"
        monkeypatch.setenv("B103_TAIL_DECOY_MARKER", str(marker))
        monkeypatch.setenv("PATH", str(decoy_path) + os.pathsep + os.environ.get("PATH", ""))
        monkeypatch.chdir(decoy_cwd)
        original_run = clipboard_module.subprocess.run
        started = []

        def recording_run(argv, **kwargs):
            started.append((list(argv), dict(kwargs)))
            return original_run(argv, **kwargs)

        monkeypatch.setattr(clipboard_module.subprocess, "run", recording_run)
        for label, payload in transport_payloads:
            other_program_write(payload)
            started.clear()
            value = clipboard_module.read_os_clipboard(strategies=strategies)
            separate = other_program_read()
            _require(value == payload, f"forced WinCI PowerShell read changed {label} payload")
            _require(separate == payload, f"tail separate reader changed {label} payload")
            _require(len(started) == 2, "product and tail readers did not each start PowerShell")
            _require(
                all(
                    isinstance(call[0][0], str)
                    and os.path.normcase(call[0][0]) == os.path.normcase(system_ps)
                    for call in started
                ),
                "product or tail reader launched a non-system PowerShell",
            )
        _require(
            attempts == ["ctypes-win32"] * len(transport_payloads),
            "WinCI reader did not force every ctypes failure",
        )
        _require(not marker.exists(), "tail decoy PowerShell executed")

    _run_arms(monkeypatch, [
        *((label, transport_arm(payload)) for label, payload in transport_payloads),
        ("forced-reader-final-lf-and-tail-decoy", forced_reader),
    ])
    _exercise_holder_cleanup_controls()


def _winci_ready_or_skip() -> None:
    if sys.platform != "win32":
        pytest.skip("WinCI-only: isolated Windows clipboard, separate OS holder/read; not_run on Linux")
    from tests.support.b103_clipboard import clipboard_probe, require_isolated_clipboard
    require_isolated_clipboard("windows")
    usable, result = clipboard_probe()
    if not usable:
        pytest.skip(f"runner clipboard unusable: {result}")


def _note_cleanup_failure(failure, action: str, exc: BaseException):
    if failure is None:
        return exc
    failure.add_note(
        f"{action} also failed during clipboard cleanup ({type(exc).__name__})"
    )
    return failure


def _reap_holder(proc) -> None:
    """Reap one holder, always ending with a bounded wait, close and poll."""
    failure = None

    def attempt(action: str, cleanup) -> None:
        nonlocal failure
        try:
            cleanup()
        except BaseException as exc:
            failure = _note_cleanup_failure(failure, action, exc)

    def kill_if_running() -> None:
        if proc.poll() is None:
            proc.kill()

    def close_stdout() -> None:
        if proc.stdout is not None:
            proc.stdout.close()

    attempt("initial holder kill", kill_if_running)
    attempt("initial holder wait", lambda: proc.wait(timeout=3.0))
    attempt("final holder kill", kill_if_running)
    attempt("final holder wait", lambda: proc.wait(timeout=1.0))
    attempt("holder stdout close", close_stdout)
    try:
        returncode = proc.poll()
    except BaseException as exc:
        failure = _note_cleanup_failure(failure, "final holder poll", exc)
    else:
        if returncode is None:
            failure = _note_cleanup_failure(
                failure,
                "final holder poll",
                RuntimeError("clipboard holder process is still running"),
            )
    if failure is not None:
        raise failure


def _release_clipboard(state: dict) -> None:
    """Release supervisor and holder without hiding their first failure."""
    failure = state.get("supervisor_failure")

    def attempt(action: str, cleanup) -> None:
        nonlocal failure
        try:
            cleanup()
        except BaseException as exc:
            failure = _note_cleanup_failure(failure, action, exc)

    attempt("clipboard release signal", state["release"].set)
    attempt(
        "first supervisor join",
        lambda: state["supervisor"].join(timeout=5.0),
    )
    attempt("holder reap", lambda: _reap_holder(state["proc"]))
    attempt(
        "final supervisor join",
        lambda: state["supervisor"].join(timeout=1.0),
    )
    supervisor_failure = state.get("supervisor_failure")
    if supervisor_failure is not None and supervisor_failure is not failure:
        failure = _note_cleanup_failure(
            failure, "clipboard holder supervisor", supervisor_failure
        )
    try:
        supervisor_alive = state["supervisor"].is_alive()
    except BaseException as exc:
        failure = _note_cleanup_failure(failure, "final supervisor check", exc)
    else:
        if supervisor_alive:
            failure = _note_cleanup_failure(
                failure,
                "final supervisor check",
                RuntimeError("clipboard holder supervisor did not finish"),
            )
    try:
        returncode = state["proc"].poll()
    except BaseException as exc:
        failure = _note_cleanup_failure(failure, "final holder poll", exc)
    else:
        if returncode is None:
            failure = _note_cleanup_failure(
                failure,
                "final holder poll",
                RuntimeError("clipboard holder process is still running"),
            )
    if failure is not None:
        raise failure


def _hold_clipboard(seconds: float = 8.0) -> dict:
    """Acquire a guarded OS holder and reap every partial acquisition."""
    require_isolated_clipboard("windows")
    import textwrap
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
            0, "STATIC", "b103-tail-holder", 0, 0, 0, 0, 0,
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
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        ready_lines = queue.Queue(maxsize=1)

        def read_ready():
            try:
                ready_lines.put(proc.stdout.readline())
            except Exception as exc:
                ready_lines.put(exc)

        reader = threading.Thread(target=read_ready, daemon=True)
        reader.start()
        try:
            ready = ready_lines.get(timeout=5.0)
        except queue.Empty as exc:
            raise RuntimeError("clipboard holder readiness timed out") from exc
        reader.join(timeout=1.0)
        _require(not reader.is_alive(), "clipboard holder readiness reader did not finish")
        if isinstance(ready, Exception):
            raise RuntimeError("clipboard holder readiness read failed") from ready
        if ready.strip() != "HOLDING":
            raise RuntimeError("clipboard holder failed before readiness")
        if proc.poll() is not None:
            raise RuntimeError(f"clipboard holder exited after HOLDING: {proc.returncode}")

        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        user32.OpenClipboard.argtypes = [wintypes.HWND]
        user32.OpenClipboard.restype = wintypes.BOOL
        user32.CloseClipboard.argtypes = []
        user32.CloseClipboard.restype = wintypes.BOOL
        if user32.OpenClipboard(None):
            user32.CloseClipboard()
            raise RuntimeError("clipboard hold not effective")
        if proc.poll() is not None:
            raise RuntimeError("clipboard holder did not stay alive")

        state = {"proc": proc, "release": threading.Event()}

        def supervise():
            try:
                state["release"].wait(timeout=seconds)
            except BaseException as exc:
                state["supervisor_failure"] = exc
            finally:
                try:
                    _reap_holder(proc)
                except BaseException as exc:
                    state["supervisor_failure"] = _note_cleanup_failure(
                        state.get("supervisor_failure"),
                        "supervisor holder reap",
                        exc,
                    )

        supervisor = threading.Thread(target=supervise, daemon=True)
        state["supervisor"] = supervisor
        supervisor.start()
        return state
    except BaseException as exc:
        failure = exc

        def attempt(action: str, cleanup) -> None:
            nonlocal failure
            try:
                cleanup()
            except BaseException as cleanup_exc:
                failure = _note_cleanup_failure(failure, action, cleanup_exc)

        attempt("acquisition holder reap", lambda: _reap_holder(proc))
        for label, thread in (("readiness reader", reader), ("supervisor", supervisor)):
            if thread is None:
                continue
            attempt(f"{label} cleanup join", lambda: thread.join(timeout=1.0))
            try:
                alive = thread.is_alive()
            except BaseException as cleanup_exc:
                failure = _note_cleanup_failure(
                    failure, f"{label} cleanup check", cleanup_exc
                )
            else:
                if alive:
                    failure = _note_cleanup_failure(
                        failure,
                        f"{label} cleanup check",
                        RuntimeError(f"clipboard holder {label} is still running"),
                    )
        try:
            returncode = proc.poll()
        except BaseException as cleanup_exc:
            failure = _note_cleanup_failure(
                failure, "acquisition final holder poll", cleanup_exc
            )
        else:
            if returncode is None:
                failure = _note_cleanup_failure(
                    failure,
                    "acquisition final holder poll",
                    RuntimeError("clipboard holder process is still running"),
                )
        raise failure


def _run_holder_control(arm) -> None:
    outcome = queue.Queue(maxsize=1)

    def execute() -> None:
        try:
            arm()
        except BaseException as exc:
            outcome.put(exc)
        else:
            outcome.put(None)

    thread = threading.Thread(target=execute, daemon=True)
    thread.start()
    thread.join(timeout=2.0)
    _require(not thread.is_alive(), "holder cleanup control exceeded its deadline")
    try:
        failure = outcome.get_nowait()
    except queue.Empty:
        raise AssertionError("holder cleanup control returned no outcome") from None
    if failure is not None:
        raise failure


def _exercise_holder_cleanup_controls() -> None:
    class StreamDouble:
        def __init__(self, line: str = "", on_close=None) -> None:
            self.line = line
            self.on_close = on_close
            self.closed = False
            self.close_count = 0

        def readline(self) -> str:
            return self.line

        def close(self) -> None:
            self.closed = True
            self.close_count += 1
            if self.on_close is not None:
                self.on_close()

    class ProcessDouble:
        def __init__(
            self,
            *,
            line: str = "",
            returncode=None,
            defer_first_kill: bool = False,
            never_dies: bool = False,
        ) -> None:
            self.events = []
            self.stdout = StreamDouble(line, lambda: self.events.append("close"))
            self.returncode = returncode
            self.defer_first_kill = defer_first_kill
            self.never_dies = never_dies
            self.poll_count = 0
            self.kill_count = 0
            self.kill_errors = []
            self.wait_timeouts = []
            self.wait_alive_states = []
            self.wait_errors = []

        def poll(self):
            self.poll_count += 1
            self.events.append("poll")
            return self.returncode

        def kill(self) -> None:
            self.kill_count += 1
            self.events.append("kill")
            error = self.kill_errors.pop(0) if self.kill_errors else None
            if error is not None:
                raise error
            if self.never_dies or (self.defer_first_kill and self.kill_count == 1):
                return
            self.returncode = 0

        def wait(self, timeout: float):
            self.wait_timeouts.append(timeout)
            self.wait_alive_states.append(self.returncode is None)
            self.events.append(f"wait:{timeout}")
            error = self.wait_errors.pop(0) if self.wait_errors else None
            if error is not None:
                raise error
            return self.returncode

    def thread_type(join_error=None, start_error=None):
        class ThreadDouble:
            instances = []

            def __init__(self, target, daemon: bool) -> None:
                self.target = target
                self.daemon = daemon
                self.start_count = 0
                self.started = False
                self.join_timeouts = []
                self.__class__.instances.append(self)

            def start(self) -> None:
                self.start_count += 1
                if start_error is not None:
                    raise start_error
                self.started = True
                self.target()

            def join(self, timeout: float) -> None:
                self.join_timeouts.append(timeout)
                if join_error is not None:
                    raise join_error

            def is_alive(self) -> bool:
                return False

        return ThreadDouble

    def install_hold(patch, proc, threads, queue_type=None) -> None:
        guards = []

        def permit_guard(platform: str) -> None:
            guards.append(platform)

        def popen(*args, **kwargs):
            _require(guards == ["windows"], "holder started before its intrinsic guard")
            return proc

        patch.setattr("tests.test_b103_clipboard_tail.require_isolated_clipboard", permit_guard)
        patch.setattr(subprocess, "Popen", popen)
        patch.setattr(threading, "Thread", threads)
        if queue_type is not None:
            patch.setattr(queue, "Queue", queue_type)

    def require_reaped(proc, *, kills: int) -> None:
        _require(proc.poll_count >= 3, "cleanup control omitted its final process poll")
        _require(proc.events[-1] == "poll", "cleanup control did not end with a process poll")
        _require(proc.stdout.closed, "cleanup control did not close holder stdout")
        close_index = proc.events.index("close")
        _require("poll" in proc.events[close_index + 1:], "cleanup control did not poll after close")
        _require(proc.kill_count == kills, "cleanup control issued an unexpected kill count")
        _require(proc.wait_timeouts == [3.0, 1.0], "cleanup control did not perform both bounded waits")
        _require(proc.poll() is not None, "cleanup control left its process alive")

    def guard_rejected() -> None:
        import ctypes

        primary = OSError("clipboard isolation rejected")
        resources = []

        class ForbiddenWin32:
            def __getattr__(self, name):
                resources.append(name)
                raise AssertionError("holder touched Win32 before its guard")

        def reject(platform: str) -> None:
            raise primary

        def forbidden_popen(*args, **kwargs):
            resources.append("Popen")
            raise AssertionError("holder started a process before its guard")

        patch = pytest.MonkeyPatch()
        try:
            patch.setattr(
                "tests.test_b103_clipboard_tail.require_isolated_clipboard", reject
            )
            patch.setattr(subprocess, "Popen", forbidden_popen)
            patch.setattr(ctypes, "windll", ForbiddenWin32(), raising=False)
            try:
                _hold_clipboard()
            except OSError as exc:
                _require(exc is primary, "guard control replaced the isolation failure")
            else:
                _require(False, "rejected guard unexpectedly acquired a holder")
        finally:
            patch.undo()
        _require(resources == [], "rejected guard touched Popen, user32 or kernel32")

    def reader_start_failure() -> None:
        proc = ProcessDouble()
        primary = OSError("readiness reader start failed")
        threads = thread_type(start_error=primary)
        patch = pytest.MonkeyPatch()
        try:
            install_hold(patch, proc, threads)
            try:
                _hold_clipboard()
            except OSError as exc:
                _require(exc is primary, "reader-start cleanup replaced its primary failure")
            else:
                _require(False, "reader-start failure unexpectedly acquired a holder")
        finally:
            patch.undo()
        require_reaped(proc, kills=1)
        _require(len(threads.instances) == 1, "reader-start control did not create its reader")
        reader = threads.instances[0]
        _require(reader.start_count == 1 and not reader.started, "reader-start failure was not injected")
        _require(reader.join_timeouts == [1.0], "reader-start cleanup did not join the reader")

    def readiness_absent() -> None:
        proc = ProcessDouble()
        join_failure = OSError("readiness reader join failed")
        threads = thread_type(join_failure)

        class EmptyQueue:
            def __init__(self, maxsize: int) -> None:
                pass

            def put(self, value) -> None:
                pass

            def get(self, timeout: float):
                raise queue.Empty

        patch = pytest.MonkeyPatch()
        try:
            install_hold(patch, proc, threads, EmptyQueue)
            try:
                _hold_clipboard()
            except RuntimeError as exc:
                _require(str(exc) == "clipboard holder readiness timed out", "readiness control lost its primary failure")
                _require(
                    any(
                        "readiness reader cleanup join" in note
                        for note in getattr(exc, "__notes__", [])
                    ),
                    "readiness cleanup did not preserve its secondary failure as a note",
                )
            else:
                _require(False, "readiness absence unexpectedly acquired a holder")
        finally:
            patch.undo()
        require_reaped(proc, kills=1)
        _require(len(threads.instances) == 1, "readiness control did not create its reader")
        _require(threads.instances[0].join_timeouts == [1.0], "readiness cleanup did not join the reader")

    def death_after_holding() -> None:
        proc = ProcessDouble(line="HOLDING\n", returncode=1)
        threads = thread_type()
        patch = pytest.MonkeyPatch()
        try:
            install_hold(patch, proc, threads)
            try:
                _hold_clipboard()
            except RuntimeError as exc:
                _require("exited after HOLDING" in str(exc), "death-after-HOLDING control missed its branch")
            else:
                _require(False, "dead holder unexpectedly remained acquired")
        finally:
            patch.undo()
        require_reaped(proc, kills=0)
        _require(len(threads.instances) == 1, "death control did not create its reader")
        _require(threads.instances[0].join_timeouts == [1.0, 1.0], "death cleanup did not repeat the reader join")

    def wait_timeout() -> None:
        proc = ProcessDouble(defer_first_kill=True)
        primary = subprocess.TimeoutExpired("holder", 3.0)
        proc.wait_errors = [primary]
        try:
            _reap_holder(proc)
        except subprocess.TimeoutExpired as exc:
            _require(exc is primary, "wait timeout cleanup replaced the primary failure")
        else:
            _require(False, "wait timeout unexpectedly succeeded")
        require_reaped(proc, kills=2)
        _require(
            proc.wait_alive_states == [True, False],
            "wait timeout did not stay alive until the final kill and wait",
        )
        _require(proc.stdout.close_count == 1, "wait timeout cleanup closed stdout more than once")

    def kill_failure() -> None:
        proc = ProcessDouble()
        primary = OSError("holder kill failed")
        proc.kill_errors = [primary, None]
        try:
            _reap_holder(proc)
        except OSError as exc:
            _require(exc is primary, "kill failure cleanup replaced the primary failure")
        else:
            _require(False, "kill failure unexpectedly succeeded")
        require_reaped(proc, kills=2)
        _require(
            proc.wait_alive_states == [True, False],
            "kill retry did not perform both bounded waits around the final kill",
        )

    def holder_never_dies() -> None:
        proc = ProcessDouble(never_dies=True)
        try:
            _reap_holder(proc)
        except RuntimeError as exc:
            _require(
                str(exc) == "clipboard holder process is still running",
                "unkillable holder raised the wrong final-poll failure",
            )
        else:
            _require(False, "unkillable holder unexpectedly passed cleanup")
        _require(proc.kill_count == 2, "unkillable holder did not receive both kill attempts")
        _require(proc.wait_timeouts == [3.0, 1.0], "unkillable holder omitted a bounded wait")
        _require(proc.wait_alive_states == [True, True], "unkillable holder double did not stay alive")
        _require(proc.stdout.close_count == 1, "unkillable holder stdout was not closed exactly once")
        _require(proc.events[-1] == "poll", "unkillable holder did not end with a final poll")

    class ReleaseDouble:
        def __init__(self, failure=None) -> None:
            self.failure = failure
            self.set_count = 0

        def set(self) -> None:
            self.set_count += 1
            if self.failure is not None:
                raise self.failure

    class SupervisorDouble:
        def __init__(self, *, alive: bool, join_failure=None) -> None:
            self.alive = alive
            self.join_failure = join_failure
            self.join_timeouts = []
            self.on_join = None

        def join(self, timeout: float) -> None:
            self.join_timeouts.append(timeout)
            if self.on_join is not None:
                self.on_join()
            if self.join_failure is not None:
                raise self.join_failure

        def is_alive(self) -> bool:
            return self.alive

    def release_state(*, alive: bool, release_failure=None, join_failure=None):
        proc = ProcessDouble()
        release = ReleaseDouble(release_failure)
        supervisor = SupervisorDouble(alive=alive, join_failure=join_failure)
        return {"proc": proc, "release": release, "supervisor": supervisor}

    def require_release_cleanup(state, *, joins: list[float]) -> None:
        _require(state["release"].set_count == 1, "release cleanup did not signal the supervisor")
        _require(state["supervisor"].join_timeouts == joins, "release cleanup did not attempt both joins")
        require_reaped(state["proc"], kills=1)

    def supervisor_hung() -> None:
        state = release_state(alive=True)
        try:
            _release_clipboard(state)
        except RuntimeError as exc:
            _require(str(exc) == "clipboard holder supervisor did not finish", "hung supervisor raised the wrong failure")
        else:
            _require(False, "hung supervisor unexpectedly passed release")
        require_release_cleanup(state, joins=[5.0, 1.0])

    def release_failure() -> None:
        primary = OSError("release signal failed")
        state = release_state(alive=False, release_failure=primary)
        try:
            _release_clipboard(state)
        except OSError as exc:
            _require(exc is primary, "release failure was replaced during cleanup")
        else:
            _require(False, "release failure unexpectedly succeeded")
        require_release_cleanup(state, joins=[5.0, 1.0])

    def join_failure() -> None:
        primary = OSError("supervisor join failed")
        state = release_state(alive=False, join_failure=primary)
        try:
            _release_clipboard(state)
        except OSError as exc:
            _require(exc is primary, "join failure was replaced during cleanup")
        else:
            _require(False, "join failure unexpectedly succeeded")
        require_release_cleanup(state, joins=[5.0, 1.0])

    def supervisor_wait_failure() -> None:
        primary = OSError("supervisor release wait failed")
        state = release_state(alive=False)

        def publish_failure() -> None:
            state["supervisor_failure"] = primary

        state["supervisor"].on_join = publish_failure
        try:
            _release_clipboard(state)
        except OSError as exc:
            _require(exc is primary, "supervisor failure was replaced during cleanup")
        else:
            _require(False, "supervisor failure unexpectedly succeeded")
        require_release_cleanup(state, joins=[5.0, 1.0])

    def release_holder_alive() -> None:
        state = release_state(alive=False)
        state["proc"] = ProcessDouble(never_dies=True)
        try:
            _release_clipboard(state)
        except RuntimeError as exc:
            _require(
                str(exc) == "clipboard holder process is still running",
                "live holder raised the wrong release failure",
            )
        else:
            _require(False, "live holder unexpectedly passed release")
        _require(state["release"].set_count == 1, "live-holder release did not signal the supervisor")
        _require(
            state["supervisor"].join_timeouts == [5.0, 1.0],
            "live-holder release omitted either supervisor join",
        )
        proc = state["proc"]
        _require(proc.kill_count == 2, "live-holder release omitted its final kill")
        _require(proc.wait_timeouts == [3.0, 1.0], "live-holder release omitted a bounded wait")
        _require(proc.stdout.closed, "live-holder release did not close stdout")
        _require(proc.events[-1] == "poll", "live-holder release did not end with a poll")

    for control in (
        guard_rejected,
        reader_start_failure,
        readiness_absent,
        death_after_holding,
        wait_timeout,
        kill_failure,
        holder_never_dies,
        supervisor_hung,
        release_failure,
        join_failure,
        supervisor_wait_failure,
        release_holder_alive,
    ):
        _run_holder_control(control)


def _allow_real_processes(monkeypatch, ledger, original_run) -> None:
    def process_spy(argv, **kwargs):
        ledger.counts["process"] += 1
        ledger.processes.append((list(argv), dict(kwargs)))
        return original_run(argv, **kwargs)
    monkeypatch.setattr(clipboard_module.subprocess, "run", process_spy)


@pytest.mark.serial_timing
def test_r_paste_13_101_held_row_copy_warns_within_bound(tmp_path, monkeypatch) -> None:
    """R-PASTE.13/101: held row write ends within 2.5 s, one cascade."""
    _winci_ready_or_skip()
    other_program_write(SEED_OS)
    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            table, expected = await _a2l_third_row(app, pilot, tmp_path)
            real_run = clipboard_module.subprocess.run
            ledger = _instrument(app, monkeypatch, writer_result=None)
            _allow_real_processes(monkeypatch, ledger, real_run)
            held = _hold_clipboard()
            try:
                started = time.monotonic()
                await _right_click(app, pilot, table, (4, table.header_height + 2))
                await _wait(
                    pilot,
                    lambda: bool(ledger.writer_done) and bool(ledger.tail_done),
                    timeout=10.0,
                )
                elapsed = time.monotonic() - started
            finally:
                _release_clipboard(held)
            return elapsed, _observe(app, ledger, expected=expected)
    elapsed, obs = asyncio.run(drive())
    _failure(obs, obs["expected"], view=True)
    _require(obs["counts"]["writer"] == 1, "held copy did not perform exactly one writer call")
    bound = timing_bound(2.5)
    assert elapsed <= report_margin("r_paste_13_101_row", elapsed, bound), elapsed


_TRACE_SKIP = frozenset({"Timer", "Idle"})
CONTROL_WRITE_S = 1.5


def _trace_screen_spans(app, monkeypatch, diag: dict) -> None:
    """Diagnostics only: record the layout (L) and paint (P) spans of the screen."""
    screen = app.screen
    for name, tag in (("_refresh_layout", "L"), ("_compositor_refresh", "P")):
        original = getattr(screen, name)

        def timed(*args, _original=original, _tag=tag, **kwargs):
            began = time.monotonic()
            try:
                return _original(*args, **kwargs)
            finally:
                diag["spans"].append((_tag, began, time.monotonic() - began))

        monkeypatch.setattr(screen, name, timed)


STALL_GAP_S = 0.15
STALL_POLL_S = 0.02
STALL_CAPTURES = 3
STALL_FRAMES = 12


def _frame_module(filename: str) -> str:
    """A dotted module name relative to the repo, site-packages or the stdlib
    (the shortest match wins); otherwise the file's base name. Never a path."""
    paths = sysconfig.get_paths()
    path = Path(filename)
    best = None
    for root in (REPO_ROOT, Path(paths["purelib"]), Path(paths["platlib"]), Path(paths["stdlib"])):
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if best is None or len(rel.parts) < len(best.parts):
            best = rel
    name = ".".join(best.parts) if best is not None else path.name
    return name[:-3] if name.endswith(".py") else name


def _loop_stack(loop_ident: int) -> list:
    frame = sys._current_frames().get(loop_ident)
    if frame is None:
        return ["<no loop frame>"]
    rows = traceback.extract_stack(frame)[-STALL_FRAMES:]
    return [f"{_frame_module(row.filename)}:{row.name}:{row.lineno}" for row in rows]


class _StallSampler:
    """Diagnostics only (P-001 round 4). Started by the marked writer after it
    stamps ``t_start`` and stopped when it stamps ``t_end``: every 20 ms it
    checks the last tick of ``ticks``; when none ran for more than 150 ms it
    captures the loop thread's stack, once per stall, at most 3 times. It also
    records its own largest wake gap (a gap far above 20 ms means this thread
    could not run either: GIL held in C code, or the process not scheduled)."""

    def __init__(self, loop_ident: int, ticks: list) -> None:
        self.loop_ident = loop_ident
        self.ticks = ticks
        self.stop = threading.Event()
        self.captures: list = []
        self.max_wake_gap = 0.0
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        began = woke = time.monotonic()
        captured_for = None
        while not self.stop.wait(STALL_POLL_S):
            now = time.monotonic()
            self.max_wake_gap = max(self.max_wake_gap, now - woke)
            woke = now
            last = max(self.ticks[-1][1] if self.ticks else began, began)
            if now - last <= STALL_GAP_S or last == captured_for:
                continue
            if len(self.captures) < STALL_CAPTURES:
                self.captures.append((now, now - last, _loop_stack(self.loop_ident)))
            captured_for = last


def _gc_hook(events_out: list, loop_ident: int):
    """Diagnostics only: ``gc.callbacks`` start/stop with the generation."""

    def hook(phase: str, info: dict) -> None:
        on_loop = threading.get_ident() == loop_ident
        events_out.append((time.monotonic(), phase, info.get("generation"), on_loop))

    return hook


def _gc_collections(diag: dict, start: float, end: float) -> list:
    rows, began = [], None
    for at, phase, generation, on_loop in diag.get("gc", []):
        if phase == "start":
            began = at
        elif began is not None:
            if start <= began <= end:
                rows.append((generation, began, at - began, on_loop))
            began = None
    return rows


def _round4_report(diag: dict, start: float, end: float) -> str:
    """Round-4 additions: loop stalls with stacks, GC in the write, sampler wake gap."""
    rows = _gc_collections(diag, start, end)
    per_gen = Counter(gen for gen, _at, _took, _loop in rows)
    secs = {gen: round(sum(took for g, _a, took, _l in rows if g == gen), 4) for gen in per_gen}
    longest = sorted(rows, key=lambda row: row[2], reverse=True)[:5]
    gc_long = [
        f"g{gen}{at - start:+.3f}/{took:.4f}{'' if on_loop else '(other thread)'}"
        for gen, at, took, on_loop in longest
    ]
    sampler = diag.get("sampler")
    stalls = [
        f"{at - start:+.3f} gap={gap:.3f} stack=" + " > ".join(stack)
        for at, gap, stack in (sampler.captures if sampler else [])
    ]
    wake = f"{sampler.max_wake_gap:.3f}" if sampler else "n/a"
    return (
        f" | gc_in_write count={dict(per_gen)} secs={secs} longest(start/dur)={gc_long}"
        f" | sampler_max_wake_gap={wake} | loop_stalls>{STALL_GAP_S}s={stalls}"
    )


def _responsive_report(marker, lateness, diag: dict) -> str:
    """A few-KB timeline around the write, relative to ``t_start``; no payloads."""
    start = marker.get("t_start")
    if start is None:
        return "no t_start stamp"
    end = marker.get("t_end", start)
    low, high = start - 0.3, end + 0.1

    def rel(value: float) -> str:
        return f"{value - start:+.3f}"

    ticks = [f"{rel(due)}/{now - due:.3f}" for due, now in diag["ticks"] if low <= due <= high]
    spans = [row for row in diag["spans"] if row[1] + row[2] >= low and row[1] <= high]
    long_spans = [f"{tag}{rel(began)}/{took:.3f}" for tag, began, took in spans if took >= 0.005]
    in_write = Counter(name for at, name in diag["messages"] if start <= at <= end)
    in_write["Callback"] = sum(1 for at in diag["callbacks"] if start <= at <= end)
    bins = [0] * (int((end - start) / 0.1) + 1)
    for at in diag["callbacks"]:
        if start <= at <= end:
            bins[int((at - start) / 0.1)] += 1
    near = [
        f"{rel(at)} {name}"
        for at, name in diag["messages"]
        if low <= at <= high and name not in ("Update", "Layout")
    ]
    offset = diag.get("wall_offset", 0.0)
    notices = [
        f"{rel(raised - offset)} {severity} "
        + " ".join(re.sub(r"[^A-Za-z ]", " ", message).split()[:2])
        for raised, severity, message in diag.get("notices", [])
    ]
    return (
        f"max_late={max(lateness, default=0.0):.3f} n={len(lateness)} t_end={rel(end)}"
        f" | ticks(due/late)={ticks[:50]}"
        f" | spans>=5ms(start/dur)={long_spans[:30]}"
        f" paint_s={sum(row[2] for row in spans if row[0] == 'P'):.3f}"
        f" layout_s={sum(row[2] for row in spans if row[0] == 'L'):.3f}"
        f" | msgs_in_write={dict(in_write.most_common(8))}"
        f" | callbacks_per_100ms={bins[:40]}"
        f" | events={near[:25]}"
        f" | notices={notices[:6]}"
        + _round4_report(diag, start, end)
    )


async def _wait_sleep_only(predicate, timeout: float) -> None:
    """``_wait`` without ``pilot.pause()``: no Pilot ``Callback`` messages (C2)."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError("fixture predicate not satisfied before timeout")
        await asyncio.sleep(0.02)


def _responsive_copy(
    tmp_path, monkeypatch, source: str, *, control: bool = False, sleep_poll: bool = False
):
    diag: dict = {"ticks": [], "spans": [], "messages": [], "callbacks": [], "gc": [], "armed": False}

    def message_hook(message) -> None:
        if not diag["armed"]:
            return
        name = type(message).__name__
        if name == "Callback":
            # Pilot.pause posts one per widget (_wait_for_screen): counted, not listed.
            diag["callbacks"].append(time.monotonic())
        elif name not in _TRACE_SKIP and len(diag["messages"]) < 20_000:
            diag["messages"].append((time.monotonic(), name))

    async def drive():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54), message_hook=message_hook) as pilot:
            await _settle(pilot)
            if source == "key":
                expected = await _select_hex(app, pilot, tmp_path)
                widget = app.query_one("#hex_view")
            elif source == "right":
                expected = await _select_hex(app, pilot, tmp_path)
                widget = app.query_one("#hex_view")
            else:
                widget, expected = await _a2l_third_row(app, pilot, tmp_path)
            if control:
                # The no-write control: the same app and gesture, the OS
                # write replaced by an off-thread sleep that then fails.
                ledger = _instrument(
                    app, monkeypatch, writer_result=False, writer_delay=CONTROL_WRITE_S
                )
            else:
                real_run = clipboard_module.subprocess.run
                ledger = _instrument(app, monkeypatch, writer_result=None)
                _allow_real_processes(monkeypatch, ledger, real_run)
            _trace_screen_spans(app, monkeypatch, diag)
            recorded_writer = clipboard_module.write_os_clipboard
            marker = {"started": False, "ended": False}
            loop_ident = threading.get_ident()
            sampler = diag["sampler"] = _StallSampler(loop_ident, diag["ticks"])
            def marked_writer(text, *args, **kwargs):
                marker["t_start"] = time.monotonic()
                marker["started"] = True
                if sampler.thread.ident is None:
                    sampler.thread.start()
                try:
                    return recorded_writer(text, *args, **kwargs)
                finally:
                    marker["t_end"] = time.monotonic()
                    marker["ended"] = True
                    sampler.stop.set()
            monkeypatch.setattr(clipboard_module, "write_os_clipboard", marked_writer)
            held = None if control else _hold_clipboard()
            gc_hook = _gc_hook(diag["gc"], loop_ident)
            gc.callbacks.append(gc_hook)
            diag["armed"] = True
            try:
                async for lateness in arm_tick_lateness(app, marker, trace=diag["ticks"]):
                    if source == "key":
                        await pilot.press("ctrl+c")
                        await _settle(pilot, 1)
                    elif source == "right":
                        await _right_click(app, pilot, widget, (10, 2))
                    else:
                        await _right_click(app, pilot, widget, (4, widget.header_height + 2))
                    def done() -> bool:
                        return marker["ended"] and bool(ledger.tail_done)
                    if sleep_poll:
                        await _wait_sleep_only(done, timeout=10.0)
                    else:
                        await _wait(pilot, done, timeout=10.0)
                    await _settle(pilot)
                    break
            finally:
                gc.callbacks.remove(gc_hook)
                sampler.stop.set()
                if sampler.thread.ident is not None:
                    sampler.thread.join(1.0)
                if held is not None:
                    _release_clipboard(held)
            diag["notices"] = [
                (float(n.raised_at), str(n.severity), str(n.message))
                for n in list(app._notifications)
            ]
            diag["wall_offset"] = time.time() - time.monotonic()
            return marker, lateness, _observe(app, ledger, expected=expected), diag
    return asyncio.run(drive())


def _assert_responsive(marker, lateness, obs, label: str, diag: dict) -> None:
    _failure(obs, obs["expected"], view=True)
    _require(marker["started"] and marker["ended"], "responsive writer did not run to completion")
    _require(obs["writer_threads"] and obs["writer_threads"][0] != threading.get_ident(), "responsive writer ran on the UI thread")
    report = _responsive_report(marker, lateness, diag)
    _require(len(lateness) >= 10, "responsive writer control recorded too few ticks: " + report)
    bound = timing_bound(0.1)
    _require(max(lateness) <= report_margin(label, max(lateness), bound), "responsive writer exceeded its tick bound: " + report)


def test_r_paste_14_101_view_key_write_stays_responsive(tmp_path, monkeypatch) -> None:
    """R-PASTE.14/101: view-key writer is off-thread and ticks stay bounded."""
    _winci_ready_or_skip()
    other_program_write(SEED_OS)
    marker, lateness, obs, diag = _responsive_copy(tmp_path, monkeypatch, "key")
    _assert_responsive(marker, lateness, obs, "r_paste_14_101_key", diag)


def test_r_paste_14_102_view_right_write_stays_responsive(tmp_path, monkeypatch) -> None:
    """R-PASTE.14/102: view-right writer is off-thread and ticks stay bounded."""
    _winci_ready_or_skip()
    other_program_write(SEED_OS)
    marker, lateness, obs, diag = _responsive_copy(tmp_path, monkeypatch, "right")
    _assert_responsive(marker, lateness, obs, "r_paste_14_102_right", diag)


def test_r_paste_14_103_row_right_write_stays_responsive(tmp_path, monkeypatch) -> None:
    """R-PASTE.14/103: row-right writer is off-thread and ticks stay bounded."""
    _winci_ready_or_skip()
    other_program_write(SEED_OS)
    marker, lateness, obs, diag = _responsive_copy(tmp_path, monkeypatch, "row")
    _assert_responsive(marker, lateness, obs, "r_paste_14_103_row", diag)


@pytest.mark.parametrize("source", ["key", "right", "row"], ids=["key", "right", "row"])
def test_r_paste_14_c1_no_write_control_full_app(tmp_path, monkeypatch, source: str) -> None:
    """R-PASTE.14/C1 (control for /101 … /103): the same full app and gesture
    with the OS write replaced by an off-thread 1.5 s sleep. Same window and
    the same bound: a FAIL here means the app's own render cost, not the write."""
    _winci_ready_or_skip()
    other_program_write(SEED_OS)
    marker, lateness, obs, diag = _responsive_copy(tmp_path, monkeypatch, source, control=True)
    _assert_responsive(marker, lateness, obs, f"r_paste_14_c1_{source}", diag)


def test_r_paste_14_c2_sleep_poll_control_full_app(tmp_path, monkeypatch) -> None:
    """R-PASTE.14/C2 (diagnostic control, P-001 round 4): C1[key] with its wait
    loop polling ``asyncio.sleep(0.02)`` instead of ``pilot.pause()``. Same
    window, skips and bound. A PASS while C1 FAILs puts the stall on the Pilot
    ``Callback`` storm; a FAIL puts it elsewhere."""
    _winci_ready_or_skip()
    other_program_write(SEED_OS)
    marker, lateness, obs, diag = _responsive_copy(
        tmp_path, monkeypatch, "key", control=True, sleep_poll=True
    )
    _assert_responsive(marker, lateness, obs, "r_paste_14_c2_key", diag)


def _line_cut_observation(tmp_path: Path, monkeypatch) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            widget = await _show_box(app, pilot, "textarea", "first\nline_to_cut\nthird", select=False)
            widget.selection = ((1, 2), (1, 2))
            await _settle(pilot)
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await pilot.press("ctrl+x")
            await _wait_copy_tail(pilot, ledger)
            return _observe(app, ledger, after_text=widget.text)
    return asyncio.run(drive())


def _unrelated_view_box_observation(tmp_path: Path, monkeypatch) -> dict:
    async def drive() -> dict:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(118, 54)) as pilot:
            await _settle(pilot)
            await _load_example(app, pilot, tmp_path, "prg.s19")
            await _load_example(app, pilot, tmp_path, "ASAP2_Demo_V171.a2l")
            app.action_show_screen("a2l")
            await _settle(pilot)
            app.screen.clear_selection()
            await pilot.mouse_down("#alt_hex_view", offset=(2, 1))
            await pilot.hover("#alt_hex_view", offset=(40, 5))
            await pilot.mouse_up("#alt_hex_view", offset=(40, 5))
            await _settle(pilot)
            unrelated = app.screen.get_selected_text()
            _require(bool(unrelated) and unrelated.count("\n") == 2, "unrelated selection did not contain three lines")
            _require(len(set(unrelated.splitlines())) == 3, "unrelated selection lines were not distinct")
            view_selections = dict(app.screen.selections)
            box = app.query_one("#a2l_tags_filter_input", Input)
            box.value = "abc"
            box.selection = (0, 3)
            box.focus()
            await _settle(pilot)
            app.screen.selections.update(view_selections)
            _require(app.screen.get_selected_text() == unrelated, "unrelated view selection was not restored")
            _require(box.selection == (0, 3), "direct box selection changed before copying")
            ledger = _instrument(app, monkeypatch, writer_result=True)
            await _right_click(app, pilot, box)
            await _wait_copy_tail(pilot, ledger)
            return _observe(
                app,
                ledger,
                expected="abc",
                unrelated=unrelated,
                after_text=box.value,
                after_selection=box.selection,
            )

    return asyncio.run(drive())
