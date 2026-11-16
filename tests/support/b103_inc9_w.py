"""Inc 9 E4 (tests, tester T9b): the shared drivers of the ``test_b103_inc9_w_*``, ``_a9`` and ``_i`` files.

Everything drives the shipped chain: the real ``S19TuiApp`` under Textual Pilot, the app's own A2L / image
loaders, the Patch Editor screen as the operator opens it, keys through ``pilot.press``. Expected values come
from the requirements, from I-2 (``a2l_definition``) and from the committed example oracle ``EX``
(``evidence-e1/examples_inc9.py``); nothing is read from the implementation of ``bench_sheet.py``.

Interface readings (``codewire/graph-inc9.md`` I-9.1, pinned there): ``sheet.states[name]`` is a ``BenchState``
(``cursor``, ``anchor``, ``tool`` as the key letter, ``edit`` position -> text, ``undo``, ``focus``, ``values``,
``staged``, ``strip``, ``preview``, ``job``, ``status``); ``sheet.generation`` is an int that grows at every
``set_document``; ``sheet.record_staged(name, edit)`` and ``sheet.record_done(name)`` exist. A job is held by
``Gate`` (a wrapper around the I-2 call, found wherever the product imported it), never by a product hook.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest

from s19_app.tui import a2l_definition
from tests.b97_probes import painted_rows, record_statuses  # noqa: F401  (re-exported)
from tests.conftest import _s19_data_record, _s19_header_record, _s19_terminator
from tests.support import b103_a2l_arrays as arrays
from tests.support.b103_inc8_p import SIZE, WIDE, build_defc, drive, need  # noqa: F401  (re-exported)

BODY, INPUT, SHEET, TAIL = "#patch_sheet_body", "#patch_sheet_input", "#patch_sheet", "#patch_sheet_tail"
VB, MAP, CURVE, DISPLAY = "VAL_BLK_DEF_0001", "MAP_DEF_0001", "CURVE_DEF_0001", "DISPLAY_0001"
LARGE_COUNT = 1048576
BIG_COUNT = 70000  # more than 4,096 elements, decodes in about a second: stands for LARGE where only the job logic matters
HOLD_LIMIT_S = 20.0


@pytest.fixture(scope="session")
def defc_dir(tmp_path_factory) -> Path:
    """DEFC (``make_release_case.py --case definitions``, seed 20260001) written by the shipped generator."""
    return build_defc(tmp_path_factory.mktemp("b103_inc9_w_defc"))


def run(tmp_path, defc_dir, body, *, size=SIZE, a2l=None, image=None, patch=None):
    """Open the Patch Editor on DEFC (or on ``a2l`` / ``image`` paths) and await ``body(app, pilot, panel)``."""
    return drive(tmp_path, size, body, a2l=a2l or defc_dir / "definitions.a2l",
                 image=image or defc_dir / "definitions.s19", patch=patch)


def hand_case(tmp_path, blocks, memory) -> tuple[Path, Path]:
    """A hand A2L of ``blocks`` and an S19 image of ``memory`` ((address, bytes) pairs); returns both paths."""
    arrays.inline(tmp_path, *blocks)
    a2l = tmp_path / f"inline3_{arrays._counter[0]}.a2l"
    lines = [_s19_header_record()]
    for address, data in memory:
        for at in range(0, len(data), 240):
            lines.append(_s19_data_record(address + at, bytes(data[at:at + 240])))
    lines.append(_s19_terminator())
    s19 = tmp_path / f"hand_{arrays._counter[0]}.s19"
    s19.write_text("\n".join(lines) + "\n", encoding="ascii")
    return a2l, s19


def valblk_block(name: str, address: int, count: int, hi: str = "255") -> str:
    return arrays.valblk(name, f"0x{address:X}", "RL_U8", "NO_COMPU_METHOD", "0", hi, f"MATRIX_DIM {count}")


def big_case(tmp_path, count=LARGE_COUNT, rows=("LARGE",)):
    """``rows`` objects of ``count`` UBYTE elements over ONE shared zero image, plus SMALL_BLK (1 2 3 4)."""
    blocks = [valblk_block(name, 0x100000, count) for name in rows]
    blocks.append(valblk_block("SMALL_BLK", 0x400000, 4))
    return hand_case(tmp_path, blocks, [(0x100000, bytes(count)), (0x400000, bytes([1, 2, 3, 4]))])


def sheet_of(panel):
    """The panel's sheet, which must be the bench sheet (C-1)."""
    from s19_app.tui.screens_directionb.patch_editor.bench_sheet import ArrayBenchSheet

    return need(panel, SHEET, ArrayBenchSheet)


def st(sheet, name):
    """The bench state of ``name`` (None before its first selection)."""
    return sheet.states.get(name)


async def wait_for(pilot, predicate, what: str, timeout: float = 30.0, delay: float = 0.02) -> None:
    """Bounded real-delay pump-until: jobs run on worker threads and need wall time."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        await pilot.pause(delay)
        if predicate():
            return
    raise AssertionError(f"did not settle within {timeout} s: {what}")


async def pick(pilot, sheet, name: str) -> None:
    """Select the row ``name`` with the arrow keys the operator uses (never by poking ``selected``)."""
    state = st(sheet, sheet.selected_name) if sheet.selected_name else None
    if state is not None and state.focus:
        await pilot.press("escape")
    elif getattr(pilot.app.focused, "id", None) == "patch_sheet_input":
        await pilot.press("escape")
    if getattr(pilot.app.focused, "id", None) != BODY[1:]:
        # I9: the arrows select a row only while the sheet holds the focus (R-PE-DEF.45); the operator clicks or
        # tabs into it first, as Inc 8's key tests do.
        sheet.query_one(BODY).focus()
        await pilot.pause()
    names = [row.name for row in sheet.rows]
    assert name in names, f"{name} is not on the page {names}"
    for _ in range(len(names) + 2):
        if sheet.selected_name == name:
            return
        await pilot.press("down" if names.index(name) > names.index(sheet.selected_name) else "up")
        await pilot.pause()
    assert sheet.selected_name == name, f"could not select {name}"


def has_values(sheet, name: str) -> bool:
    state = st(sheet, name)
    return state is not None and state.values is not None


async def open_bench(pilot, sheet, name: str, *, decoded: bool = True) -> None:
    """Select ``name`` and press Enter: the bench holds the focus; wait for its values unless ``decoded`` is False."""
    await pick(pilot, sheet, name)
    await wait_for(pilot, lambda: st(sheet, name) is not None, f"the bench state of {name}", 10)
    if not st(sheet, name).focus:
        await pilot.press("enter")
        await pilot.pause()
    assert st(sheet, name).focus, f"Enter did not give the bench of {name} the focus"
    if decoded:
        await wait_for(pilot, lambda: has_values(sheet, name), f"the values of {name}", 90)


async def apply_tool(pilot, sheet, key: str, operand: str, *, back: bool = True) -> None:
    """From the bench focus: tool ``key``, Enter to the op input, the operand, Enter (apply), Escape back
    to the bench unless ``back`` is False (the focus then stays in the op input, R-PE-BENCH.51)."""
    await pilot.press(key, "enter")
    await pilot.pause()
    assert getattr(pilot.app.focused, "id", None) == "patch_sheet_input", "Enter did not reach the op input"
    need(sheet, INPUT).value = operand
    await pilot.pause()
    await pilot.press("enter")
    await pilot.pause()
    if back:
        await pilot.press("escape")
        await pilot.pause()


async def edited(pilot, sheet, name: str, expect: dict) -> None:
    await wait_for(pilot, lambda: dict(st(sheet, name).edit) == expect, f"the bench edit of {name} = {expect}")


def body_text(app) -> str:
    return "\n".join(painted_rows(app, need(app.screen, BODY)))


def tail_text(app) -> str:
    """The op line's tail as plain text (Inc 8's own reader: the Static's ``content``)."""
    content = need(app.screen, TAIL).content
    return content.plain if hasattr(content, "plain") else str(content)


def service_of(app):
    return app._change_service


def entries_of(app) -> list:
    return [(e.address, bytes(e.encoded_bytes)) for e in service_of(app).document.entries]


class Gate:
    """A wrapper around I-2's ``decode_values`` / ``encode_values`` that counts calls and holds named objects.

    The wrapper replaces the function wherever the product imported it (every ``s19_app`` module attribute that
    is the original), so no import style escapes it. It never changes a result. ``calls`` holds
    ``(function, object name, on the UI thread)`` for the outermost call of each thread; ``peak`` is the most
    outermost calls running at once. A held call waits for ``release()`` at most ``HOLD_LIMIT_S`` seconds.
    """

    def __init__(self, monkeypatch, *functions: str, hold=()):
        self.calls, self.hold, self.running, self.peak = [], set(hold), 0, 0
        self.entered, self.released = threading.Event(), threading.Event()
        self._lock, self._local = threading.Lock(), threading.local()
        for function in functions:
            self._wrap(monkeypatch, function)

    def _wrap(self, monkeypatch, function: str) -> None:
        original, gate = getattr(a2l_definition, function), self

        def wrapper(definition, *args, **kwargs):
            outer = gate._begin(function, definition.name)
            try:
                return original(definition, *args, **kwargs)
            finally:
                gate._end(outer)

        for module in list(sys.modules.values()):
            if str(getattr(module, "__name__", "")).startswith("s19_app") and getattr(module, function, None) is original:
                monkeypatch.setattr(module, function, wrapper)

    def _begin(self, function: str, name: str) -> bool:
        depth = getattr(self._local, "depth", 0)
        self._local.depth = depth + 1
        if depth:
            return False
        with self._lock:
            self.calls.append((function, name, threading.current_thread() is threading.main_thread()))
            self.running += 1
            self.peak = max(self.peak, self.running)
        if name in self.hold:
            self.entered.set()
            self.released.wait(HOLD_LIMIT_S)
        return True

    def _end(self, outer: bool) -> None:
        self._local.depth -= 1
        if outer:
            with self._lock:
                self.running -= 1

    def release(self) -> None:
        self.released.set()

    def names(self, function: str) -> list:
        return [name for fn, name, _ in self.calls if fn == function]

    def on_ui_thread(self) -> list:
        return [call for call in self.calls if call[2]]
