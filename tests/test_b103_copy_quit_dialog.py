"""Batch-103 Inc-1b E4/E5: quit dialog, modal guard and deferred quit.

Oracles are the concrete examples in inc-1b/01-requirements.md,
02-test-cases.md, codewire/graph-inc1b.md and E2-interfaces.md. Every new
product symbol is resolved lazily. Linux uses a seeded in-memory recorder.
The nine R-COPY.16/.20 partial routes also have an isolated WinCI arm with
an external seed and separate exact OS reads; Linux passes do not close it.
"""
from __future__ import annotations

import ast
import asyncio
import os
import shutil
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from rich.text import Text
from textual.actions import SkipAction
from textual.app import App
from textual.geometry import Offset
from textual.selection import Selection
from textual.widgets import Static

from s19_app.tui.app import S19TuiApp
from tests.b97_probes import is_displayed
from tests.support.b100_workers import settle_workers
from tests.support.b103_clipboard import (
    clipboard_probe,
    other_program_read,
    other_program_write,
    require_isolated_clipboard,
)
from tests.support.timing import report_margin, timing_bound

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "case_00_public"
SIZE = (118, 54)
WIDE = (220, 60)
SEED = "SEED-1b"
BODY_B = "Quit the app? Nothing is selected to copy."
QUIT_TEXTS = ("Quit?", BODY_B, "Quit (y)", "Stay (n)")


@dataclass
class _ClipboardRecorder:
    os_value: str = SEED
    os_seeded: bool = False
    writes: list[str] = field(default_factory=list)
    reads: list[str] = field(default_factory=list)
    base_calls: list[str] = field(default_factory=list)
    entries: list[str] = field(default_factory=list)
    skips: list[str] = field(default_factory=list)
    workers: list[tuple] = field(default_factory=list)
    osc52: list[str] = field(default_factory=list)
    pushes: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self.os_value = SEED
        for values in (
            self.writes,
            self.reads,
            self.base_calls,
            self.entries,
            self.skips,
            self.workers,
            self.osc52,
            self.pushes,
        ):
            values.clear()


@pytest.fixture(autouse=True)
def clipboard(monkeypatch: pytest.MonkeyPatch):
    recorder = _ClipboardRecorder()
    from s19_app.tui import capped_text_area as capped
    from s19_app.tui import os_clipboard_input as os_clipboard

    if sys.platform == "win32":
        require_isolated_clipboard("windows")
        try:
            usable, _detail = clipboard_probe()
        except pytest.skip.Exception:
            raise AssertionError("isolated WinCI clipboard probe failed") from None
        if not usable:
            pytest.fail("isolated WinCI clipboard probe failed", pytrace=False)

    real_write = os_clipboard.write_os_clipboard

    def write(text, *args, **kwargs):
        recorder.writes.append(text)
        if sys.platform == "win32":
            return real_write(text, *args, **kwargs)
        recorder.os_value = text
        return True

    def read(*args, **kwargs):
        recorder.reads.append("recorded-read")
        return recorder.os_value

    monkeypatch.setattr(os_clipboard, "write_os_clipboard", write)
    if sys.platform != "win32":
        monkeypatch.setattr(os_clipboard, "read_os_clipboard", read)
        monkeypatch.setattr(os_clipboard, "_prime_tk_root", lambda: None, raising=False)
        monkeypatch.setattr(capped, "write_os_clipboard", write, raising=False)
        monkeypatch.setattr(capped, "read_os_clipboard", read, raising=False)

    real_base = App.copy_to_clipboard

    def base_copy(app, text):
        recorder.base_calls.append(text)
        return real_base(app, text)

    monkeypatch.setattr(App, "copy_to_clipboard", base_copy)
    return recorder


def _read_os_clipboard_exact() -> str:
    return other_program_read()


def _seed_os_clipboard() -> None:
    other_program_write(SEED)
    if _read_os_clipboard_exact() != SEED:
        pytest.fail("WinCI seed read-back failed before copy", pytrace=False)


def _check_winci_external_round_trips() -> None:
    for label, expected in (
        ("unicode", "SEED-Ω-漢字-🙂"),
        ("cr", "L1\rL2"),
        ("lf", "L1\nL2"),
        ("final-lf", "L1\nL2\n"),
    ):
        other_program_write(expected)
        actual = other_program_read()
        if actual != expected:
            pytest.fail(
                "WinCI external clipboard round-trip failed: "
                f"{label}; expected_chars={len(expected)}; actual_chars={len(actual)}",
                pytrace=False,
            )


def _stack(app) -> list[str]:
    return [type(screen).__name__ for screen in app.screen_stack]


def _notes(app) -> list[tuple[str, str, str, float]]:
    return [
        (str(note.message), str(note.severity), str(note.title), float(note.timeout))
        for note in list(app._notifications)
    ]


def _running(app) -> bool:
    return bool(app.is_running and app.return_code is None)


async def _settle(app, pilot, count: int = 6) -> None:
    for _ in range(count):
        if not app.is_running:
            return
        await pilot.pause(0.02)


async def _wait(pilot, predicate, description: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise AssertionError(f"fixture timed out: {description}")
        await pilot.pause(0.02)


async def _wait_exit(app, timeout: float | None = None) -> bool:
    if timeout is None:
        timeout = timing_bound(1.0)
    deadline = time.monotonic() + timeout
    while app.return_code is None:
        if time.monotonic() >= deadline:
            return False
        await asyncio.sleep(0.01)
    return True


async def _load_census(app, pilot) -> None:
    app.base_dir.mkdir(parents=True, exist_ok=True)
    for name in ("prg.s19", "synthetic_update_test1.mac", "ASAP2_Demo_V171.a2l"):
        copied = app.base_dir / name
        shutil.copyfile(EXAMPLES / name, copied)
        if name.endswith(".a2l"):
            app.load_a2l_from_path(copied)
            await _wait(
                pilot,
                lambda: getattr(app, "current_a2l_data", None) is not None
                and Path(app.current_a2l_path).name == name,
                f"A2L census load {name}",
            )
        else:
            app.load_from_path(copied)
            if name.endswith(".s19"):
                await _wait(
                    pilot,
                    lambda: app.current_file is not None
                    and Path(app.current_file.path).name == name,
                    f"image census load {name}",
                )
            else:
                await _wait(
                    pilot,
                    lambda: app.current_file is not None
                    and getattr(app.current_file, "mac_path", None) is not None
                    and Path(app.current_file.mac_path).name == name,
                    f"MAC census load {name}",
                )
        await _settle(app, pilot, 3)
    await settle_workers(pilot)
    await _settle(app, pilot, 4)


def _install_recorders(app, recorder: _ClipboardRecorder) -> None:
    real_entry = app.copy_to_clipboard

    def entry(text):
        recorder.entries.append(text)
        try:
            return real_entry(text)
        except SkipAction:
            recorder.skips.append(text)
            raise

    app.copy_to_clipboard = entry

    real_worker = app.run_worker

    def worker(*args, **kwargs):
        recorder.workers.append((args, kwargs))
        return real_worker(*args, **kwargs)

    app.run_worker = worker

    real_push = app.push_screen

    def push(screen, *args, **kwargs):
        recorder.pushes.append(type(screen).__name__)
        return real_push(screen, *args, **kwargs)

    app.push_screen = push

    real_write = app._driver.write

    def write(data):
        if "\x1b]52;" in data:
            recorder.osc52.append(data)
        return real_write(data)

    app._driver.write = write


def _run(
    base: Path,
    scenario,
    recorder: _ClipboardRecorder,
    *,
    size=SIZE,
    winci_seed=False,
):
    async def drive():
        app = S19TuiApp(base_dir=base)
        async with app.run_test(size=size, notifications=True) as pilot:
            _install_recorders(app, recorder)
            await _load_census(app, pilot)
            app._clipboard = SEED
            recorder.reset()
            recorder.os_seeded = False
            if winci_seed and sys.platform == "win32":
                _seed_os_clipboard()
                recorder.os_seeded = True
            app._notifications.clear()
            return await scenario(app, pilot)

    return asyncio.run(drive())


def _plain_and_spans(widget) -> tuple[str, list]:
    renderable = getattr(widget, "label", None)
    if renderable is None:
        renderable = getattr(widget, "renderable", None)
    if renderable is None:
        renderable = widget.render()
    if isinstance(renderable, Text):
        return renderable.plain, list(renderable.spans)
    plain = getattr(renderable, "plain", None)
    spans = getattr(renderable, "spans", None)
    if plain is not None and spans is not None:
        return str(plain), list(spans)
    text = Text(str(renderable))
    return text.plain, list(text.spans)


def _plain(widget) -> str:
    return _plain_and_spans(widget)[0]


def _spans(widget) -> list:
    return _plain_and_spans(widget)[1]


def _copy_screens(app) -> list:
    return [screen for screen in app.screen_stack if type(screen).__name__ == "_CopyQuitScreen"]


def _busy_screens(app) -> list:
    return [screen for screen in app.screen_stack if type(screen).__name__ == "_QuitQuestionScreen"]


def _question_texts(screen) -> tuple[str, str, str, str]:
    return tuple(
        _plain(screen.query_one(selector))
        for selector in ("#confirm_title", "#confirm_body", "#confirm_yes", "#confirm_no")
    )


def _assert_copy_quit_dialog(app):
    screens = _copy_screens(app)
    assert len(screens) == 1, {
        "stack": _stack(app),
        "notes": _notes(app),
        "running": _running(app),
    }
    screen = screens[0]
    assert app.screen is screen, _stack(app)
    assert _question_texts(screen) == QUIT_TEXTS, _question_texts(screen)
    for selector in ("#confirm_title", "#confirm_body"):
        widget = screen.query_one(selector)
        assert _spans(widget) == [], (selector, _plain(widget), _spans(widget))
    for selector in ("#confirm_yes", "#confirm_no"):
        assert _spans(screen.query_one(selector)) == [], selector
    return screen


def _assert_busy_quit_dialog(app, label: str):
    screens = _busy_screens(app)
    assert len(screens) == 1, {"stack": _stack(app), "notes": _notes(app)}
    assert app.screen is screens[0], _stack(app)
    expected = (
        "Quit?",
        f"still working: {label} — wait, or quit after it finishes",
        "Quit (y)",
        "Stay (n)",
    )
    assert _question_texts(screens[0]) == expected, _question_texts(screens[0])
    assert _copy_screens(app) == [], _stack(app)
    return screens[0]


def _assert_no_copy_effects(app, recorder: _ClipboardRecorder, *, empty_skip=False) -> None:
    if empty_skip:
        assert recorder.entries == [""], recorder.entries
        assert recorder.skips == [""], {
            "entries": recorder.entries,
            "skips": recorder.skips,
            "note": "materialized empty text must raise textual.actions.SkipAction",
        }
    assert app.clipboard == SEED, app.clipboard
    if recorder.os_seeded:
        if _read_os_clipboard_exact() != SEED:
            pytest.fail("WinCI OS clipboard seed changed", pytrace=False)
    elif sys.platform != "win32":
        assert recorder.os_value == SEED, recorder.os_value
    assert recorder.writes == [], recorder.writes
    assert recorder.base_calls == [], recorder.base_calls
    assert recorder.workers == [], recorder.workers
    assert recorder.osc52 == [], recorder.osc52
    assert _notes(app) == [], _notes(app)


def _focus_search(app) -> None:
    app.action_show_screen("workspace")
    app.query_one("#search_button").focus()
    app.screen.clear_selection()


def _materialize_empty_selection(screen) -> None:
    widgets = list(screen.query("#hex_view"))
    if not widgets:
        widgets = [widget for widget in screen.query("*") if isinstance(widget, Static)]
    assert widgets, type(screen).__name__
    screen.selections[widgets[0]] = Selection(Offset(0, 0), Offset(0, 0))
    assert screen.selections, "the empty selection must be materialized"
    assert screen.get_selected_text() == "", screen.get_selected_text()


def _inside(inner, outer) -> bool:
    return (
        inner.x >= outer.x
        and inner.y >= outer.y
        and inner.right <= outer.right
        and inner.bottom <= outer.bottom
    )


def _assert_dialog_geometry(app) -> None:
    body = app.screen.query_one("#confirm_body")
    box = app.screen.query_one("#confirm_box")
    assert body.region.height == 1, body.region
    assert body.region.width >= len(BODY_B), body.region
    for selector in ("#confirm_yes", "#confirm_no"):
        button = app.screen.query_one(selector)
        assert is_displayed(button), selector
        assert button.region.width > 0 and button.region.height > 0, button.region
        assert _inside(button.region, box.region), (selector, button.region, box.region)
        assert _inside(button.region, app.screen.region), (selector, button.region, app.screen.region)


async def _open_empty_copy_dialog(
    app,
    pilot,
    recorder: _ClipboardRecorder,
    *,
    materialized=False,
    geometry=False,
):
    recorder.reset()
    app._notifications.clear()
    if materialized:
        _materialize_empty_selection(app.screen)
    await pilot.press("ctrl+c")
    await _settle(app, pilot)
    if materialized:
        _assert_no_copy_effects(app, recorder, empty_skip=True)
    screen = _assert_copy_quit_dialog(app)
    _assert_no_copy_effects(app, recorder)
    if geometry:
        _assert_dialog_geometry(app)
    return screen


async def _close_and_assert_unchanged(app, pilot, recorder: _ClipboardRecorder, key="n") -> None:
    await pilot.press(key)
    await _settle(app, pilot)
    assert _running(app), (key, app.return_code)
    assert _copy_screens(app) == [], _stack(app)
    _assert_no_copy_effects(app, recorder)


async def _answer_and_time(pilot, app, gesture) -> float:
    label = os.environ.get("PYTEST_CURRENT_TEST", "quit_answer").split(" ")[0].rsplit("::", 1)[-1]
    bound = timing_bound(1.0)
    started = time.monotonic()
    await gesture()
    exited = await _wait_exit(app, bound)
    elapsed = time.monotonic() - started
    assert exited and app.return_code == 0, (app.return_code, elapsed, bound, _stack(app))
    assert elapsed <= report_margin(label, elapsed, bound), (elapsed, bound)
    return elapsed


class _HeldFileLoad:
    def __init__(self, monkeypatch: pytest.MonkeyPatch):
        self.main = threading.get_ident()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.main_calls: list = []
        real = S19TuiApp._parse_data_file

        def held(app, path, *args, **kwargs):
            if Path(path).name != "held.s19":
                return real(app, path, *args, **kwargs)
            if threading.get_ident() == self.main:
                self.main_calls.append(path)
                return real(app, path, *args, **kwargs)
            if not self.entered.is_set():
                self.entered.set()
                if not self.release.wait(60.0):
                    raise TimeoutError("held.s19 was not released")
            return real(app, path, *args, **kwargs)

        monkeypatch.setattr(S19TuiApp, "_parse_data_file", held)

    async def wait(self, pilot) -> None:
        deadline = time.monotonic() + 15.0
        while not self.entered.is_set():
            assert not self.main_calls, "held file parse ran on the event-loop thread"
            if time.monotonic() >= deadline:
                raise AssertionError("fixture timed out: held.s19 did not reach its worker")
            await pilot.pause(0.01)
        await pilot.pause()

    async def release_and_drain(self, app, pilot) -> None:
        self.release.set()
        if app.is_running and not getattr(app, "_quit_pending", False):
            await settle_workers(pilot)
            await _settle(app, pilot, 3)


async def _start_held_load(app, pilot, hold: _HeldFileLoad) -> str:
    copied = app.base_dir / "held.s19"
    shutil.copyfile(EXAMPLES / "prg.s19", copied)
    app.load_from_path(copied)
    await hold.wait(pilot)
    run = app._running_session_action()
    assert run is not None and run.label == "Loading held.s19", run
    _focus_search(app)
    await _settle(app, pilot, 3)
    return "Loading held.s19"


# R-COPY.16 — empty Ctrl+C opens exactly the body-B dialog.


def test_r_copy_16_1_button_and_materialized_empty_selection(tmp_path: Path, clipboard) -> None:
    """R-COPY.16/1; mutation: return normally for "" instead of SkipAction."""
    failures = []
    for size in (SIZE, WIDE):
        for materialized in (False, True):
            async def scenario(app, pilot):
                _focus_search(app)
                await _settle(app, pilot, 3)
                await _open_empty_copy_dialog(
                    app, pilot, clipboard, materialized=materialized, geometry=True
                )
                await _close_and_assert_unchanged(app, pilot, clipboard)

            try:
                _run(
                    tmp_path / f"{size[0]}-{materialized}",
                    scenario,
                    clipboard,
                    size=size,
                    winci_seed=True,
                )
            except AssertionError as error:
                failures.append(f"size={size}, materialized={materialized}: {error}")
    assert failures == [], "\n".join(failures)


def test_r_copy_16_2_no_widget_focused(tmp_path: Path, clipboard) -> None:
    """R-COPY.16/2; mutation: require a focused widget for the fallback."""
    async def scenario(app, pilot):
        app.screen.set_focus(None)
        app.screen.clear_selection()
        await _settle(app, pilot, 3)
        assert app.focused is None
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


def test_r_copy_16_3_highlighted_table_row_is_not_selection(tmp_path: Path, clipboard) -> None:
    """R-COPY.16/3; mutation: treat the highlighted A2L row as a copy selection."""
    async def scenario(app, pilot):
        await pilot.press("2")
        await _settle(app, pilot, 4)
        table = app.query_one("#a2l_tags_list")
        table.focus()
        await pilot.press("down", "down")
        await _settle(app, pilot, 3)
        assert table.cursor_row == 2, table.cursor_row
        app.screen.clear_selection()
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


def test_r_copy_16_4_empty_single_line_input(tmp_path: Path, clipboard) -> None:
    """R-COPY.16/4; mutation: copy an empty string or swallow the input SkipAction."""
    async def scenario(app, pilot):
        await pilot.press("2")
        await _settle(app, pilot, 4)
        await pilot.press("/")
        await _settle(app, pilot, 4)
        field = app.query_one("#a2l_tags_filter_input")
        field.focus()
        await _settle(app, pilot, 2)
        assert app.focused is field and field.value == ""
        app.screen.clear_selection()
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


def test_r_copy_16_5_empty_json_selection(tmp_path: Path, clipboard) -> None:
    """R-COPY.16/5; mutation: let an empty JSON selection suppress the fallback."""
    async def scenario(app, pilot):
        app.action_show_screen("patch")
        await _settle(app, pilot, 3)
        await pilot.click("#patch_tab_json")
        await pilot.click("#patch_json_view")
        await _settle(app, pilot, 3)
        view = app.query_one("#patch_json_view")
        assert app.focused is view and view.selected_text == ""
        app.screen.clear_selection()
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


def test_r_copy_16_6_multiline_text_without_selection(tmp_path: Path, clipboard) -> None:
    """R-COPY.16/6; mutation: confuse non-empty document text with a selection."""
    async def scenario(app, pilot):
        app.action_show_screen("patch")
        await _settle(app, pilot, 3)
        await pilot.click("#patch_tab_json")
        await _settle(app, pilot, 2)
        view = app.query_one("#patch_paste_text")
        view.load_text("L1")
        view.cursor_location = view.document.end
        view.focus()
        await _settle(app, pilot, 3)
        assert view.text == "L1" and view.selected_text == ""
        app.screen.clear_selection()
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


# R-COPY.17/.18 — answers, timing and safe emphasis.


@pytest.mark.serial_timing
def test_r_copy_17_1_y_quits_within_one_second(tmp_path: Path, clipboard) -> None:
    """R-COPY.17/1; mutation: dismiss True but keep the app running."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _answer_and_time(pilot, app, lambda: pilot.press("y"))

    _run(tmp_path / "app", scenario, clipboard)


@pytest.mark.serial_timing
def test_r_copy_17_2_tab_enter_on_quit(tmp_path: Path, clipboard) -> None:
    """R-COPY.17/2; mutation: Tab does not move Stay -> Quit before Enter."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        assert getattr(app.focused, "id", None) == "confirm_no"
        await pilot.press("tab")
        await _settle(app, pilot, 2)
        assert getattr(app.focused, "id", None) == "confirm_yes", app.focused
        await _answer_and_time(pilot, app, lambda: pilot.press("enter"))

    _run(tmp_path / "app", scenario, clipboard)


@pytest.mark.serial_timing
def test_r_copy_17_3_click_quit(tmp_path: Path, clipboard) -> None:
    """R-COPY.17/3; mutation: the Quit button paints but does not answer True."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        hit = False

        async def click():
            nonlocal hit
            hit = await pilot.click("#confirm_yes")

        await _answer_and_time(pilot, app, click)
        assert hit is True

    _run(tmp_path / "app", scenario, clipboard)


def test_r_copy_18_1_stay_has_confirm_emphasis(tmp_path: Path, clipboard) -> None:
    """R-COPY.18/1; mutation: put modal-confirm on destructive Quit."""
    async def scenario(app, pilot):
        _focus_search(app)
        screen = await _open_empty_copy_dialog(app, pilot, clipboard)
        yes = screen.query_one("#confirm_yes")
        no = screen.query_one("#confirm_no")
        assert "modal-confirm" in no.classes, no.classes
        assert "modal-confirm" not in yes.classes, yes.classes

    _run(tmp_path / "app", scenario, clipboard)


# R-COPY.19/.20 — busy and modal routing.


def test_r_copy_19_1_busy_ctrl_c_opens_busy_question(tmp_path: Path, clipboard, monkeypatch) -> None:
    """R-COPY.19/1; mutation: open body B and permit exit during a held load."""
    hold = _HeldFileLoad(monkeypatch)

    async def scenario(app, pilot):
        try:
            label = await _start_held_load(app, pilot, hold)
            clipboard.reset()
            app._notifications.clear()
            await pilot.press("ctrl+c")
            await _settle(app, pilot)
            _assert_busy_quit_dialog(app, label)
            _assert_no_copy_effects(app, clipboard)
            await pilot.press("n")
            await _settle(app, pilot, 3)
        finally:
            await hold.release_and_drain(app, pilot)

    _run(tmp_path / "app", scenario, clipboard)


def test_r_copy_20_1_help_modal_blocks_quit_even_with_empty_selection(tmp_path: Path, clipboard) -> None:
    """R-COPY.20/1; mutation: normal return for modal "" changes seeds/stack."""
    for materialized in (False, True):
        async def scenario(app, pilot):
            await pilot.press("question_mark")
            await _settle(app, pilot, 5)
            original = app.screen
            assert type(original).__name__ == "WindowHelpScreen", _stack(app)
            original_stack = list(app.screen_stack)
            if materialized:
                _materialize_empty_selection(original)
            else:
                original.clear_selection()
            clipboard.reset()
            app._notifications.clear()
            _assert_no_copy_effects(app, clipboard)
            await pilot.press("ctrl+c")
            await _settle(app, pilot)
            assert app.screen is original, _stack(app)
            assert list(app.screen_stack) == original_stack, _stack(app)
            assert _copy_screens(app) == [], _stack(app)
            _assert_no_copy_effects(app, clipboard, empty_skip=materialized)
            await pilot.press("escape")
            await _settle(app, pilot, 3)
            _assert_no_copy_effects(app, clipboard)

        _run(tmp_path / f"app-{materialized}", scenario, clipboard, winci_seed=True)


def test_r_copy_20_2_load_dialog_stays_top(tmp_path: Path, clipboard) -> None:
    """R-COPY.20/2; mutation: stack body B over the Load dialog."""
    async def scenario(app, pilot):
        _focus_search(app)
        await pilot.press("l")
        await _settle(app, pilot, 5)
        original = app.screen
        original_stack = list(app.screen_stack)
        assert type(original).__name__ == "LoadDialog", _stack(app)
        clipboard.reset()
        app._notifications.clear()
        _assert_no_copy_effects(app, clipboard)
        await pilot.press("ctrl+c")
        await _settle(app, pilot)
        assert app.screen is original, _stack(app)
        assert list(app.screen_stack) == original_stack, _stack(app)
        assert _copy_screens(app) == [], _stack(app)
        _assert_no_copy_effects(app, clipboard)
        await pilot.press("escape")
        await _settle(app, pilot, 3)
        _assert_no_copy_effects(app, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


def test_r_copy_20_3_existing_copy_quit_stays_single(tmp_path: Path, clipboard) -> None:
    """R-COPY.20/3; mutation: Ctrl+C stacks a second _CopyQuitScreen."""
    async def scenario(app, pilot):
        _focus_search(app)
        screen = await _open_empty_copy_dialog(app, pilot, clipboard)
        original_stack = list(app.screen_stack)
        await pilot.press("ctrl+c")
        await _settle(app, pilot)
        assert app.screen is screen, _stack(app)
        assert list(app.screen_stack) == original_stack, _stack(app)
        assert len(_copy_screens(app)) == 1, _stack(app)
        _assert_no_copy_effects(app, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard, winci_seed=True)


def test_r_copy_20_4_busy_question_stays_top(tmp_path: Path, clipboard, monkeypatch) -> None:
    """R-COPY.20/4; mutation: Ctrl+C over the busy question opens body B."""
    hold = _HeldFileLoad(monkeypatch)

    async def scenario(app, pilot):
        try:
            label = await _start_held_load(app, pilot, hold)
            clipboard.reset()
            app._notifications.clear()
            await pilot.press("ctrl+c")
            await _settle(app, pilot)
            original = _assert_busy_quit_dialog(app, label)
            original_stack = list(app.screen_stack)
            await pilot.press("ctrl+c")
            await _settle(app, pilot)
            assert app.screen is original, _stack(app)
            assert list(app.screen_stack) == original_stack, _stack(app)
            assert _copy_screens(app) == [], _stack(app)
            _assert_no_copy_effects(app, clipboard)
            await pilot.press("n")
            await _settle(app, pilot, 3)
        finally:
            await hold.release_and_drain(app, pilot)

    _run(tmp_path / "app", scenario, clipboard)


# R-COPY.23/.24 — q asks; Ctrl+Q and palette Quit remain immediate.


def test_r_copy_23_1_idle_q_asks_without_selection(tmp_path: Path, clipboard) -> None:
    """R-COPY.23/1; mutation: retain q -> quit and exit before confirmation."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        assert app._running_session_action() is None
        clipboard.reset()
        app._notifications.clear()
        await pilot.press("q")
        await _settle(app, pilot)
        _assert_copy_quit_dialog(app)
        assert _running(app), app.return_code
        assert _busy_screens(app) == [], _stack(app)
        _assert_no_copy_effects(app, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard)


def test_r_copy_23_2_q_with_selection_and_second_q_stays_single(tmp_path: Path, clipboard) -> None:
    """R-COPY.23/2; mutations: copy on q, quit on q, or stack on second q."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        await pilot.mouse_down("#hex_view", offset=(2, 1))
        await pilot.hover("#hex_view", offset=(40, 3))
        await pilot.mouse_up("#hex_view", offset=(40, 3))
        await _settle(app, pilot, 4)
        selected = app.screen.get_selected_text()
        assert selected is not None and len(selected.splitlines()) == 3, selected
        clipboard.reset()
        app._notifications.clear()
        await pilot.press("q")
        await _settle(app, pilot)
        _assert_copy_quit_dialog(app)
        assert _running(app), app.return_code
        if app.is_running:
            await pilot.press("q")
            await _settle(app, pilot)
        _assert_copy_quit_dialog(app)
        assert _running(app), app.return_code
        assert len(_copy_screens(app)) == 1, _stack(app)
        _assert_no_copy_effects(app, clipboard)
        assert clipboard.entries == [], clipboard.entries
        await _close_and_assert_unchanged(app, pilot, clipboard)

    _run(tmp_path / "app", scenario, clipboard)


@pytest.mark.serial_timing
def test_r_copy_24_1_ctrl_q_quits_immediately(tmp_path: Path, clipboard) -> None:
    """R-COPY.24/1; mutation: route Ctrl+Q through either confirmation."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        assert app._running_session_action() is None
        clipboard.reset()
        app._notifications.clear()
        await _answer_and_time(pilot, app, lambda: pilot.press("ctrl+q"))
        assert clipboard.pushes == [], clipboard.pushes
        assert _copy_screens(app) == [] and _busy_screens(app) == [], _stack(app)

    _run(tmp_path / "app", scenario, clipboard)


@pytest.mark.serial_timing
def test_r_copy_24_2_palette_quit_quits_immediately(tmp_path: Path, clipboard) -> None:
    """R-COPY.24/2; mutation: project palette Quit to help_quit or duplicate it."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        assert app._running_session_action() is None
        await pilot.press("ctrl+k")
        await _settle(app, pilot, 5)
        field = app.query_one("#palette_input")
        assert app.focused is field, app.focused
        await pilot.press(*"Quit")
        await _settle(app, pilot, 3)
        assert field.value == "Quit", field.value
        clipboard.reset()
        app._notifications.clear()
        await _answer_and_time(pilot, app, lambda: pilot.press("enter"))
        assert clipboard.pushes == [], clipboard.pushes
        assert _copy_screens(app) == [] and _busy_screens(app) == [], _stack(app)

    _run(tmp_path / "app", scenario, clipboard)


# Cited dialog rows /101 and R-QUIT.8/101.


def test_r_dlg_1_101_window_keys_do_not_act_behind_dialog(tmp_path: Path, clipboard) -> None:
    """R-DLG.1/101; mutation: let 1/2/slash/q reach the Workspace behind N9."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        shown = app._active_screen_key
        depth = len(app.screen_stack)
        for key in ("1", "2", "/", "q"):
            if app.is_running:
                await pilot.press(key)
                await _settle(app, pilot, 3)
            _assert_copy_quit_dialog(app)
            assert _running(app), (key, app.return_code)
            assert app._active_screen_key == shown, (key, app._active_screen_key)
            assert len(app.screen_stack) == depth, (key, _stack(app))
        _assert_no_copy_effects(app, clipboard)

    _run(tmp_path / "app", scenario, clipboard)


def test_r_dlg_2_101_escape_answers_stay(tmp_path: Path, clipboard) -> None:
    """R-DLG.2/101; mutation: Escape exits or fails to restore search-button focus."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard, key="escape")
        assert app.focused is app.query_one("#search_button"), app.focused

    _run(tmp_path / "app", scenario, clipboard)


def test_r_dlg_6_101_initial_focus_is_stay(tmp_path: Path, clipboard) -> None:
    """R-DLG.6/101; mutation: AUTO_FOCUS targets confirm_yes."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        assert getattr(app.focused, "id", None) == "confirm_no", app.focused

    _run(tmp_path / "app", scenario, clipboard)


def test_r_dlg_9_101_click_stay_preserves_window_scroll_and_state(tmp_path: Path, clipboard) -> None:
    """R-DLG.9/101; mutation: Stay changes window, scroll or pending quit."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        shown = app._active_screen_key
        scroll = app.query_one("#hex_scroll").scroll_offset
        await _open_empty_copy_dialog(app, pilot, clipboard)
        assert await pilot.click("#confirm_no") is True
        await _settle(app, pilot)
        assert _running(app), app.return_code
        assert len(app.screen_stack) == 1, _stack(app)
        assert app._active_screen_key == shown, app._active_screen_key
        assert app.query_one("#hex_scroll").scroll_offset == scroll, scroll
        assert app.focused is app.query_one("#search_button"), app.focused
        assert getattr(app, "_quit_pending", None) is False, app._quit_pending
        _assert_no_copy_effects(app, clipboard)

    _run(tmp_path / "app", scenario, clipboard)


def test_r_dlg_11_101_buttons_expose_exact_keys(tmp_path: Path, clipboard) -> None:
    """R-DLG.11/101; mutation: hide/rename the y/n key labels or add markup."""
    async def scenario(app, pilot):
        _focus_search(app)
        screen = await _open_empty_copy_dialog(app, pilot, clipboard)
        labels = [screen.query_one(selector).label.plain for selector in ("#confirm_yes", "#confirm_no")]
        assert labels == ["Quit (y)", "Stay (n)"], labels

    _run(tmp_path / "app", scenario, clipboard)


def test_r_dlg_12_101_n_presses_stay(tmp_path: Path, clipboard) -> None:
    """R-DLG.12/101; mutation: n quits or leaves pending quit behind."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _settle(app, pilot, 3)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _close_and_assert_unchanged(app, pilot, clipboard, key="n")
        assert app.focused is app.query_one("#search_button"), app.focused
        assert getattr(app, "_quit_pending", None) is False, app._quit_pending

    _run(tmp_path / "app", scenario, clipboard)


@pytest.mark.serial_timing
def test_r_dlg_12_102_y_presses_quit(tmp_path: Path, clipboard) -> None:
    """R-DLG.12/102; mutation: y answers Stay instead of Quit."""
    async def scenario(app, pilot):
        _focus_search(app)
        await _open_empty_copy_dialog(app, pilot, clipboard)
        await _answer_and_time(pilot, app, lambda: pilot.press("y"))

    _run(tmp_path / "app", scenario, clipboard)


def test_r_dlg_14_101_copy_quit_has_reachable_shared_opener(clipboard) -> None:
    """R-DLG.14/101; mutations: orphan N9, wrong count, or unreachable opener.

    WinCI also round-trips Unicode and exact line endings through the shared
    external writer and reader.
    """
    from tests.test_b101_reach_and_reports_escape import _read_tree, census_sources

    tree = _read_tree()
    census = census_sources(tree)
    assert len(census.dialogs) == 22, sorted(census.dialogs)
    assert "_CopyQuitScreen" in census.dialogs, sorted(census.dialogs)
    assert census.dialogs_without_opener == [], census.dialogs_without_opener
    action = "S19TuiApp.action_help_quit"
    assert action in census.actions, action
    assert {"string", "toolkit"} <= census.reasons(action), census.reasons(action)
    assert action not in census.actions_without_reach

    module = ast.parse(tree["s19_app/tui/app.py"])
    app_class = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "S19TuiApp")
    opener = next(
        (
            node
            for node in app_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "action_help_quit"
        ),
        None,
    )
    assert opener is not None, "S19TuiApp.action_help_quit is absent"
    constructions = [
        call
        for call in ast.walk(opener)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "_CopyQuitScreen"
    ]
    assert len(constructions) == 1, len(constructions)
    if sys.platform == "win32":
        _check_winci_external_round_trips()


def test_r_quit_8_101_confirmed_busy_quit_waits_for_load(tmp_path: Path, clipboard, monkeypatch) -> None:
    """R-QUIT.8/101; mutation: exit on y before the held load completes."""
    hold = _HeldFileLoad(monkeypatch)

    async def scenario(app, pilot):
        try:
            label = await _start_held_load(app, pilot, hold)
            clipboard.reset()
            app._notifications.clear()
            await pilot.press("ctrl+c")
            await _settle(app, pilot)
            _assert_busy_quit_dialog(app, label)
            await pilot.press("y")
            await _settle(app, pilot, 5)
            assert _running(app), "confirmed quit exited while held.s19 was still running"
            assert getattr(app, "_quit_pending", None) is True, app._quit_pending
        finally:
            await hold.release_and_drain(app, pilot)
        exited = await _wait_exit(app, 5.0)
        assert exited and app.return_code == 0, (exited, app.return_code)

    _run(tmp_path / "app", scenario, clipboard)
