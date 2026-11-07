"""Inc 1a E1 addendum pilot 4: what a right-click (mouse button 3) does in the text boxes today.

Safety as i1a-pilot.py: DISPLAY / WAYLAND_DISPLAY unset (asserted), no OS clipboard reachable
on this host, the headless driver writes nothing, `app._clipboard` is in-process. No product
file is changed: the subclasses below exist only in this script.

  P10  one-box app, OsClipboardInput 'AAAA-BBBB', 'AAAA' selected by keys; pilot.click(button=3)
  P11  the same for CappedTextArea
  P12  the button-3 events a box receives, by two routes: Pilot.click (bypasses App.on_event)
       and MouseDown/MouseUp posted to the App as the driver posts them (App.on_event makes the
       Click); recorded by a subclass whose handlers only record (base handlers still run)
  P13  a right-click on a box that does not have the focus: the selection the box holds when the
       button-3 mouse-down reaches it, and after
  P14  feasibility: a throwaway subclass whose _on_mouse_down calls prevent_default() for button 3
       (single click and double click), both classes
  P15  the xterm parser (also the Windows driver's, drivers/win32.py:230): SGR right press/release
  P16  the real app, A2L filter box: select 'AAAA', right-click; selection, value, app clipboard
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}")
print(f"python = {sys.version.split()[0]}; platform = {sys.platform}; DISPLAY={os.environ.get('DISPLAY')!r}")
assert not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"), "refusing: a display is set"

import textual  # noqa: E402
from textual import events  # noqa: E402
from textual._xterm_parser import XTermParser  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Button  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402
from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402

print(f"textual = {textual.__version__}")


def sel(box) -> str:
    s = box.selection
    return f"({s.start!r}, {s.end!r})"


def selected(box) -> str:
    try:
        return repr(box.selected_text)
    except Exception as exc:  # noqa: BLE001
        return f"<{type(exc).__name__}>"


class RecIn(OsClipboardInput):
    """Records the mouse events this box receives; the base handlers still run after these."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.rec: list = []

    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        self.rec.append(f"down b={event.button} sel@entry={sel(self)}")

    async def _on_mouse_up(self, event: events.MouseUp) -> None:
        self.rec.append(f"up b={event.button} sel@entry={sel(self)}")

    async def _on_click(self, event: events.Click) -> None:
        self.rec.append(f"click b={event.button} chain={event.chain} sel@entry={sel(self)}")


class RecTA(CappedTextArea):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.rec: list = []

    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        self.rec.append(f"down b={event.button} sel@entry={sel(self)}")

    async def _on_mouse_up(self, event: events.MouseUp) -> None:
        self.rec.append(f"up b={event.button} sel@entry={sel(self)}")

    async def _on_click(self, event: events.Click) -> None:
        self.rec.append(f"click b={event.button} chain={event.chain} sel@entry={sel(self)}")


class KeepIn(OsClipboardInput):
    """Feasibility only: button 3 does not reach the stock mouse-down (no cursor move)."""

    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 3:
            event.prevent_default()


class KeepTA(CappedTextArea):
    async def _on_mouse_down(self, event: events.MouseDown) -> None:
        if event.button == 3:
            event.prevent_default()


class One(App):
    def __init__(self, cls, text: str) -> None:
        super().__init__()
        self._cls = cls
        self._text = text

    def compose(self) -> ComposeResult:
        yield Button("other", id="other")
        yield self._cls(self._text, id="box")

    @property
    def box(self):
        return self.query_one("#box")


async def settle(pilot, n: int = 4) -> None:
    for _ in range(n):
        await pilot.pause()


async def select_aaaa(pilot, box) -> None:
    box.focus()
    await settle(pilot)
    if isinstance(box, CappedTextArea):
        await pilot.press("ctrl+home")
    else:
        await pilot.press("home")
    for _ in range(4):
        await pilot.press("shift+right")
    await settle(pilot)


async def app_route_right_click(app, pilot, box, dx: int, dy: int) -> None:
    """MouseDown / MouseUp posted to the App, as Driver.process_message posts them."""
    x = box.region.x + dx
    y = box.region.y + dy
    for cls in (events.MouseMove, events.MouseDown, events.MouseUp):
        button = 0 if cls is events.MouseMove else 3
        app.post_message(cls(None, x, y, 0, 0, button, False, False, False, screen_x=x, screen_y=y))
        await settle(pilot, 2)
    await settle(pilot)


async def p10_p11(cls, label: str) -> None:
    app = One(cls, "AAAA-BBBB")
    app._clipboard = "APP-BEFORE"
    async with app.run_test(size=(80, 12)) as pilot:
        box = app.box
        await select_aaaa(pilot, box)
        before = sel(box), selected(box)
        await pilot.click(box, offset=(6, 1), button=3)
        await settle(pilot)
        print(f"  {label}: before sel={before[0]} text={before[1]} | after right-click sel={sel(box)} "
              f"text={selected(box)} value={box.text if hasattr(box, 'document') else box.value!r} "
              f"app_clipboard={app._clipboard!r} focused={type(app.focused).__name__}")


async def p12(cls, label: str) -> None:
    for route in ("pilot.click", "App route"):
        app = One(cls, "AAAA-BBBB")
        async with app.run_test(size=(80, 12)) as pilot:
            box = app.box
            await select_aaaa(pilot, box)
            if route == "pilot.click":
                await pilot.click(box, offset=(6, 1), button=3)
                await settle(pilot)
            else:
                await app_route_right_click(app, pilot, box, 6, 1)
            print(f"  {label} [{route}]: events={box.rec} | sel after={sel(box)}")


async def p13(cls, label: str) -> None:
    app = One(cls, "KEEP-TEXT")
    async with app.run_test(size=(80, 12)) as pilot:
        box = app.box
        if isinstance(box, CappedTextArea):
            await select_aaaa(pilot, box)  # a selection made earlier, then the focus moves away
        app.query_one("#other", Button).focus()
        await settle(pilot)
        print(f"  {label}: unfocused sel={sel(box)} focused={type(app.focused).__name__}")
        await pilot.click(box, offset=(6, 1), button=3)
        await settle(pilot)
        print(f"  {label}: events={box.rec} | sel after={sel(box)} focused={type(app.focused).__name__}")


async def p14(cls, label: str) -> None:
    for times in (1, 2):
        app = One(cls, "AAAA-BBBB")
        async with app.run_test(size=(80, 12)) as pilot:
            box = app.box
            await select_aaaa(pilot, box)
            before = sel(box)
            await pilot.click(box, offset=(6, 1), button=3, times=times)
            await settle(pilot)
            try:
                screen_sel = repr(app.screen.get_selected_text())
            except Exception as exc:  # noqa: BLE001
                screen_sel = f"<{type(exc).__name__}>"
            print(f"  {label} times={times}: before={before} after={sel(box)} text={selected(box)} "
                  f"screen selection={screen_sel}")


def p15() -> None:
    parser = XTermParser()
    for seq, what in (("\x1b[<2;10;5M", "right press"), ("\x1b[<2;10;5m", "right release"),
                      ("\x1b[<0;10;5M", "left press"), ("\x1b[<6;10;5M", "shift+right press")):
        evs = list(parser.feed(seq))
        print(f"  {what:18} {seq!r:18} -> " + ", ".join(
            f"{type(e).__name__}(button={getattr(e, 'button', None)}, shift={getattr(e, 'shift', None)})" for e in evs))


async def p16() -> None:
    base = Path(tempfile.mkdtemp(prefix="i1a-pilot4-", dir=os.environ.get("TMPDIR", "/tmp")))
    app = S19TuiApp(base_dir=base)
    app._clipboard = "APP-BEFORE"
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause()
        app.action_show_screen("a2l")
        await settle(pilot, 3)
        box = app.query_one("#a2l_tags_filter_input", OsClipboardInput)
        hit = await pilot.click(box, offset=(2, 1))
        await settle(pilot)
        print(f"  real app: box region={box.region} content_region={box.content_region} left-click hit={hit} "
              f"focused={getattr(app.focused, 'id', None)!r}")
        rx, ry = 2, 1
        w_at, _ = app.get_widget_at(box.region.x + rx, box.region.y + ry)
        print(f"  real app: widget at box offset ({rx}, {ry}) = {type(w_at).__name__} id={w_at.id!r}")
        for ch in "AAAA-BBBB":
            await pilot.press("minus" if ch == "-" else ch)
        await pilot.press("home")
        for _ in range(4):
            await pilot.press("shift+right")
        await settle(pilot)
        n0 = len(app._notifications)
        before = sel(box), selected(box)
        hit3 = await pilot.click(box, offset=(rx, ry), button=3)
        await settle(pilot, 6)
        print(f"  real app: right-click hit={hit3}")
        notes = [n.message for n in list(app._notifications)[n0:]]
        print(f"  real app #a2l_tags_filter_input: before sel={before[0]} text={before[1]} | after sel={sel(box)} "
              f"text={selected(box)} value={box.value!r} app_clipboard={app._clipboard!r} new notices={notes} "
              f"focused={getattr(app.focused, 'id', None)!r}")
        await pilot.click(box, offset=(rx, ry), button=3)  # no selection now
        await settle(pilot, 6)
        print(f"  real app, second right-click (no selection): value={box.value!r} app_clipboard={app._clipboard!r}")


async def main() -> None:
    print("P10/P11 right-click (pilot.click button=3) on a box holding a selection")
    await p10_p11(OsClipboardInput, "OsClipboardInput")
    await p10_p11(CappedTextArea, "CappedTextArea  ")
    print("P12 events the box receives, two routes")
    await p12(RecIn, "OsClipboardInput")
    await p12(RecTA, "CappedTextArea  ")
    print("P13 right-click on a box without the focus")
    await p13(RecIn, "OsClipboardInput")
    await p13(RecTA, "CappedTextArea  ")
    print("P14 feasibility: prevent_default on button-3 mouse-down")
    await p14(KeepIn, "KeepIn (OsClipboardInput subclass)")
    await p14(KeepTA, "KeepTA (CappedTextArea subclass)  ")
    print("P15 xterm parser, SGR mouse")
    p15()
    print("P16 real app")
    await p16()


asyncio.run(main())
