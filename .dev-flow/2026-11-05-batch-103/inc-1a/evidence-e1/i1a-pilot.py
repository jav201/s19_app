"""Inc 1a E1 pilot: what e07fb00 does today on Linux, headless, with NO clipboard touched.

Safety: run with DISPLAY and WAYLAND_DISPLAY unset, so Tk cannot open any X/Wayland
connection (`tk.Tk()` fails before connecting); the Win32 and PowerShell layers return at
once off Windows; the headless driver writes nothing (OSC 52 is captured by wrapping the
driver's write in-process). `app._clipboard` is Textual's in-process string, not an OS
clipboard. The Tk stand-in of P3/P4b is `tkinter.Tcl()`: a Tcl interpreter WITHOUT Tk (no
display, no `clipboard` command at all), created on the main thread like the product's root,
so the product's own `_read_via_tk` pays the cross-thread call exactly as with a real root.

P1  Tcl build facts (threaded?).
P2  One Tcl call from an executor thread vs the main thread (the D1 mechanism).
P3  The product's `_read_via_tk` / `read_os_clipboard` with the Tcl stand-in: main vs executor.
P4  Ctrl+V latency through the real key path, both field classes: (a) as the host is (no Tk
    root possible: the hosted-CI case), (b) with the Tcl stand-in as the shared root.
P5  Ctrl+C / Ctrl+X on Linux today: notices, app clipboard, OSC 52 sent to the terminal.
P6  Terminal paste (events.Paste) into both classes: lines kept, the 65,536 limit.
P7  App-clipboard fallback into a single-line box: the 65,536 limit.
P8  Log lines of one Ctrl+V with no OS reader (level and text; no clipboard text).
P9  The same Ctrl+V latency inside the real S19TuiApp (A2L filter box), as the host is.
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}")
print(f"python = {sys.version.split()[0]}; platform = {sys.platform}; "
      f"DISPLAY={os.environ.get('DISPLAY')!r}; WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')!r}")
assert not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"), "refusing: a display is set"
import textual

print(f"textual = {textual.__version__}")

import tkinter  # noqa: E402

from textual import events  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402

from s19_app.tui import os_clipboard_input as oci  # noqa: E402
from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402
from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402

# ---------------------------------------------------------------- P1
print("\n== P1 Tcl build ==")
tcl = tkinter.Tcl()
print(f"TclVersion={tkinter.TclVersion} patchlevel={tcl.eval('info patchlevel')} "
      f"threaded={tcl.eval('set tcl_platform(threaded)')}")

# ---------------------------------------------------------------- P2
print("\n== P2 one Tcl call: main thread vs executor thread ==")


def one_call() -> str:
    t0 = time.perf_counter()
    try:
        tcl.eval("set x 1")
        res = "ok"
    except Exception as exc:  # noqa: BLE001
        res = f"{type(exc).__name__}: {exc}"
    return f"{(time.perf_counter() - t0) * 1000:.1f} ms -> {res}"


print(f"main thread    : {one_call()}")
with ThreadPoolExecutor(1) as pool:
    for i in range(2):
        print(f"executor run {i} : {pool.submit(one_call).result()}")

# ---------------------------------------------------------------- P3
print("\n== P3 product _read_via_tk / read_os_clipboard with the Tcl stand-in root ==")
print(f"retry budget in code: _TK_RETRIES={oci._TK_RETRIES} _TK_RETRY_DELAY_S={oci._TK_RETRY_DELAY_S} "
      f"_CTYPES_RETRIES={oci._CTYPES_RETRIES} _POWERSHELL_TIMEOUT_S={oci._POWERSHELL_TIMEOUT_S}")
print(f"read cascade order: {[n for n, _ in oci._STRATEGIES]}; write cascade order: {[n for n, _ in oci._WRITE_STRATEGIES]}")
print(f"PowerShell argv[0] read: {'powershell'!r} (literal in _read_via_powershell); write: {oci._POWERSHELL_WRITE_COMMAND[0]!r}")


def install_standin() -> None:
    fresh = oci._TkRootSingleton()
    fresh._root = tkinter.Tcl()  # created on the main thread, as _prime_tk_root would
    fresh.creator_thread = threading.current_thread().name
    oci._TK_ROOT = fresh


def reset_singleton() -> None:
    oci._TK_ROOT = oci._TkRootSingleton()


def timed(fn) -> str:
    t0 = time.perf_counter()
    r = fn()
    return f"{(time.perf_counter() - t0) * 1000:.1f} ms -> {r!r}"


install_standin()
print(f"_read_via_tk main thread      : {timed(oci._read_via_tk)}")
with ThreadPoolExecutor(1) as pool:
    print(f"_read_via_tk executor thread  : {pool.submit(timed, oci._read_via_tk).result()}")
    print(f"read_os_clipboard executor    : {pool.submit(timed, oci.read_os_clipboard).result()}")
print(f"_write_via_tk main thread     : {timed(lambda: oci._write_via_tk('w'))}")
with ThreadPoolExecutor(1) as pool:
    print(f"_write_via_tk executor thread : {pool.submit(timed, lambda: oci._write_via_tk('w')).result()}")
reset_singleton()
print(f"as the host is (no display): _read_via_tk main = {timed(oci._read_via_tk)}; "
      f"_TK_ROOT unavailable={oci._TK_ROOT._unavailable}")
reset_singleton()


# ---------------------------------------------------------------- harness
class Probe(App):
    def compose(self) -> ComposeResult:
        yield OsClipboardInput(id="one")
        yield CappedTextArea(id="many")


def content(w) -> str:
    return w.value if isinstance(w, OsClipboardInput) else w.text


async def paste_latency(app, pilot, widget, expected: str, budget_s: float = 8.0) -> tuple[float, str]:
    widget.focus()
    await pilot.pause()
    t0 = time.perf_counter()
    await pilot.press("ctrl+v")
    while content(widget) != expected and time.perf_counter() - t0 < budget_s:
        await pilot.pause(0.005)
    return (time.perf_counter() - t0) * 1000, content(widget)


def capture(app) -> tuple[list, list]:
    notes: list = []
    writes: list = []
    orig_notify = app.notify

    def notify(message, *a, **k):
        notes.append((k.get("severity"), str(message)))
        return orig_notify(message, *a, **k)

    app.notify = notify  # type: ignore[assignment]
    drv = app._driver
    orig_write = drv.write

    def write(data):
        writes.append(data)
        return orig_write(data)

    drv.write = write  # type: ignore[assignment]
    return notes, writes


async def p4(standin: bool) -> None:
    reset_singleton()
    if standin:
        install_standin()
    app = Probe()
    app._clipboard = "SEED-from-app-clipboard"
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        for wid in ("one", "many"):
            w = app.query_one(f"#{wid}")
            if wid == "one":
                w.value = ""
            else:
                w.text = ""
            ms, got = await paste_latency(app, pilot, w, "SEED-from-app-clipboard")
            print(f"  {type(w).__name__:<17} ctrl+v -> landed after {ms:8.1f} ms; content={got!r}")
    reset_singleton()


async def p5() -> None:
    reset_singleton()
    app = Probe()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        notes, writes = capture(app)
        one = app.query_one("#one")
        many = app.query_one("#many")
        for w, key in ((one, "ctrl+c"), (many, "ctrl+c"), (one, "ctrl+x"), (many, "ctrl+x")):
            if w is one:
                w.value = "COPYME-1"
            else:
                w.text = "COPYME-2"
            w.focus()
            await pilot.pause()
            w.select_all()
            await pilot.pause()
            notes.clear()
            writes.clear()
            app._clipboard = ""
            t0 = time.perf_counter()
            await pilot.press(key)
            for _ in range(40):
                await pilot.pause(0.01)
            osc = [x for x in writes if "\x1b]52;" in x]
            print(f"  {type(w).__name__:<17} {key}: app clipboard={app._clipboard!r}; box now={content(w)!r}; "
                  f"notices={notes}; OSC52 sequences sent={len(osc)} {osc[:1]!r}; {(time.perf_counter()-t0)*1000:.0f} ms window")
        # empty selection
        one.value = "KEEP"
        one.focus()
        await pilot.pause()
        one.cursor_position = 0
        app._clipboard = "BEFORE"
        await pilot.press("ctrl+c")
        await pilot.pause()
        print(f"  OsClipboardInput  ctrl+c, empty selection: app clipboard={app._clipboard!r}")


async def p6_p7_p8() -> None:
    reset_singleton()
    app = Probe()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        one = app.query_one("#one")
        many = app.query_one("#many")
        for w in (one, many):
            if w is one:
                w.value = ""
            else:
                w.text = ""
            w.focus()
            await pilot.pause()
            t0 = time.perf_counter()
            w.post_message(events.Paste("L1\nL2"))
            await pilot.pause()
            print(f"  P6 terminal paste 'L1\\nL2' into {type(w).__name__:<17}: {content(w)!r} ({(time.perf_counter()-t0)*1000:.1f} ms)")
        for w in (one, many):
            if w is one:
                w.value = ""
            else:
                w.text = ""
            w.focus()
            await pilot.pause()
            w.post_message(events.Paste("x" * 70000))
            await pilot.pause()
            print(f"  P6 terminal paste of 70,000 chars into {type(w).__name__:<17}: length {len(content(w))}")
        one.value = ""
        app._clipboard = "y" * 70000
        ms, got = await paste_latency(app, pilot, one, "y" * 70000, budget_s=3)
        print(f"  P7 ctrl+v, no OS reader, app clipboard 70,000 chars, into OsClipboardInput: length {len(got)}")
        # P8: log lines of one ctrl+v
        records: list = []

        class H(logging.Handler):
            def emit(self, rec):
                records.append((rec.name, rec.levelname, rec.getMessage()))

        h = H(level=logging.DEBUG)
        lg = logging.getLogger("s19_app")
        old = lg.level
        lg.setLevel(logging.DEBUG)
        lg.addHandler(h)
        one.value = ""
        app._clipboard = "SECRET-TEXT-42"
        await paste_latency(app, pilot, one, "SECRET-TEXT-42", budget_s=3)
        lg.removeHandler(h)
        lg.setLevel(old)
        print("  P8 log records of one ctrl+v (no OS reader):")
        for r in records:
            print(f"     {r}")
        print(f"  P8 clipboard text in any log record: {any('SECRET-TEXT-42' in r[2] for r in records)}")


async def p9() -> None:
    reset_singleton()
    from s19_app.tui.app import S19TuiApp

    base = Path(tempfile.mkdtemp(prefix="i1a-pilot-", dir=os.environ.get("TMPDIR", "/tmp")))
    app = S19TuiApp(base_dir=base)
    app._clipboard = "SEED-in-real-app"
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen("a2l")
        for _ in range(3):
            await pilot.pause()
        w = app.query_one("#a2l_tags_filter_input", OsClipboardInput)
        ms, got = await paste_latency(app, pilot, w, "SEED-in-real-app")
        print(f"  S19TuiApp #a2l_tags_filter_input ctrl+v (host as is) -> {ms:.1f} ms; {got!r}")
    reset_singleton()
    install_standin()
    app = S19TuiApp(base_dir=base)
    app._clipboard = "SEED-in-real-app"
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen("a2l")
        for _ in range(3):
            await pilot.pause()
        w = app.query_one("#a2l_tags_filter_input", OsClipboardInput)
        ms, got = await paste_latency(app, pilot, w, "SEED-in-real-app")
        print(f"  S19TuiApp #a2l_tags_filter_input ctrl+v (Tcl stand-in root) -> {ms:.1f} ms; {got!r}")
    reset_singleton()


print("\n== P4a Ctrl+V latency, host as is (Tk root cannot be created: no display) ==")
asyncio.run(p4(standin=False))
print("\n== P4b Ctrl+V latency, Tcl stand-in as the shared root (the cross-thread call of D1) ==")
asyncio.run(p4(standin=True))
print("\n== P5 copy / cut on Linux today ==")
asyncio.run(p5())
print("\n== P6 / P7 / P8 ==")
asyncio.run(p6_p7_p8())
print("\n== P9 real app ==")
asyncio.run(p9())
print("\npilot done")
