"""Inc 1a E1 pilot 2: the key-to-content latency of the real app, to size the paste threshold.

Same safety as i1a-pilot.py: DISPLAY / WAYLAND_DISPLAY unset (asserted), no OS clipboard
reachable on this host, the headless driver writes nothing, `app._clipboard` is in-process.

Measures, in S19TuiApp at 160x48 (A2L filter box) and in a one-box app:
  L1  typed key `a` -> the box holds `a`            (the app's own key-to-content time)
  L2  Ctrl+V (no OS reader here) -> the box holds the app clipboard text
  L3  terminal paste (events.Paste) -> the box holds the text
  L4  Ctrl+V with the Tcl stand-in root (the D1 cross-thread call), 3 runs
Each: 10 warm runs after 2 discarded; the clock starts just before the key/message is
injected and stops at the first poll (5 ms) that sees the expected content.
"""
from __future__ import annotations

import asyncio
import os
import statistics
import sys
import tempfile
import threading
import time
import tkinter
from pathlib import Path

import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}")
print(f"python = {sys.version.split()[0]}; platform = {sys.platform}; DISPLAY={os.environ.get('DISPLAY')!r}")
assert not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"), "refusing: a display is set"
print(f"cpu count = {os.cpu_count()}")

from textual import events  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402

from s19_app.tui import os_clipboard_input as oci  # noqa: E402
from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402


def standin() -> None:
    fresh = oci._TkRootSingleton()
    fresh._root = tkinter.Tcl()
    fresh.creator_thread = threading.current_thread().name
    oci._TK_ROOT = fresh


def reset() -> None:
    oci._TK_ROOT = oci._TkRootSingleton()


async def until(pilot, box, expected: str, t0: float, budget: float = 8.0) -> float:
    while box.value != expected and time.perf_counter() - t0 < budget:
        await pilot.pause(0.005)
    assert box.value == expected, (box.value, expected)
    return (time.perf_counter() - t0) * 1000


async def series(app, pilot, box, kind: str, runs: int) -> list[float]:
    out = []
    for i in range(runs + 2):
        box.value = ""
        box.focus()
        await pilot.pause()
        await pilot.pause()
        t0 = time.perf_counter()
        if kind == "typed":
            await pilot.press("a")
            ms = await until(pilot, box, "a", t0)
        elif kind == "ctrl+v":
            await pilot.press("ctrl+v")
            ms = await until(pilot, box, app._clipboard, t0)
        else:
            box.post_message(events.Paste("PASTED"))
            ms = await until(pilot, box, "PASTED", t0)
        if i >= 2:
            out.append(ms)
    return out


def fmt(xs: list[float]) -> str:
    return f"n={len(xs)} median={statistics.median(xs):.1f} ms max={max(xs):.1f} ms min={min(xs):.1f} ms"


class One(App):
    def compose(self) -> ComposeResult:
        yield OsClipboardInput(id="one")


async def run_real(stand: bool) -> None:
    reset()
    if stand:
        standin()
    base = Path(tempfile.mkdtemp(prefix="i1a-pilot2-", dir=os.environ.get("TMPDIR", "/tmp")))
    app = S19TuiApp(base_dir=base)
    app._clipboard = "SEED-0123456789"
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen("a2l")
        for _ in range(3):
            await pilot.pause()
        box = app.query_one("#a2l_tags_filter_input", OsClipboardInput)
        if stand:
            print(f"  real app, L4 ctrl+v with Tcl stand-in : {fmt(await series(app, pilot, box, 'ctrl+v', 3))}")
        else:
            print(f"  real app, L1 typed key 'a'            : {fmt(await series(app, pilot, box, 'typed', 10))}")
            print(f"  real app, L2 ctrl+v (no OS reader)    : {fmt(await series(app, pilot, box, 'ctrl+v', 10))}")
            print(f"  real app, L3 terminal paste           : {fmt(await series(app, pilot, box, 'paste', 10))}")
    reset()


async def run_one() -> None:
    reset()
    app = One()
    app._clipboard = "SEED-0123456789"
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        box = app.query_one("#one", OsClipboardInput)
        print(f"  one-box app, L1 typed key 'a'         : {fmt(await series(app, pilot, box, 'typed', 10))}")
        print(f"  one-box app, L2 ctrl+v (no OS reader) : {fmt(await series(app, pilot, box, 'ctrl+v', 10))}")
        print(f"  one-box app, L3 terminal paste        : {fmt(await series(app, pilot, box, 'paste', 10))}")
    reset()


print("\n== host as is (no Tk root possible) ==")
asyncio.run(run_real(False))
asyncio.run(run_one())
print("\n== Tcl stand-in root ==")
asyncio.run(run_real(True))
print("\npilot2 done")
