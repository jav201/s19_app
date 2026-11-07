"""E3 security probe, batch-103 Inc 1a (<runner>, headless, no clipboard).

Question: does text that arrives by a paste (the terminal route, and the
app-clipboard fallback of Ctrl+V, the route a right-click paste shares) keep
C0 controls, ESC sequences, NUL and bidi controls in the box value, and do
they reach the terminal unescaped when the box is drawn?

No clipboard is opened: DISPLAY / WAYLAND_DISPLAY are unset (asserted), the
OS layers return at once off Windows, and the headless driver writes nothing
to a terminal (its write is wrapped and recorded only).
"""
import asyncio
import os
import sys

assert not os.environ.get("DISPLAY"), "DISPLAY must be unset"
assert not os.environ.get("WAYLAND_DISPLAY"), "WAYLAND_DISPLAY must be unset"

import s19_app  # noqa: E402
import textual  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)
print("textual =", textual.__version__, "python =", sys.version.split()[0])

from textual import events  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402
from textual.widgets import Button  # noqa: E402

from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402
from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402

TITLE = "\x1b]0;PWNED-TITLE\x07"
OSC52 = "\x1b]52;c;SElKQUNL\x07"
SGR = "\x1b[5;31mBLINK"
PAYLOAD = "A" + TITLE + "B" + OSC52 + "C\x00D‮E" + SGR + "F⁦G"
MARKERS = {
    "OSC 0 title": "]0;PWNED-TITLE",
    "OSC 52 set": "]52;c;SElKQUNL",
    "SGR blink": "\x1b[5;31mBLINK",
    "NUL": "\x00",
    "RLO U+202E": "‮",
    "LRI U+2066": "⁦",
}


class OneBox(App):
    def __init__(self, cls):
        super().__init__()
        self._cls = cls

    def compose(self) -> ComposeResult:
        yield Button("other", id="other")
        if self._cls is OsClipboardInput:
            yield OsClipboardInput(id="box")
        else:
            yield CappedTextArea(id="box")


async def run(cls, route):
    app = OneBox(cls)
    writes = []
    async with app.run_test(size=(100, 20)) as pilot:
        orig = app._driver.write

        def spy(data):
            writes.append(data)
            return orig(data)

        app._driver.write = spy
        await pilot.click("#box")
        await pilot.pause()
        box = app.query_one("#box")
        if route == "terminal paste":
            app.post_message(events.Paste(PAYLOAD))
        else:  # Ctrl+V with no OS clipboard -> app clipboard fallback
            app._clipboard = PAYLOAD
            await pilot.press("ctrl+v")
        for _ in range(4):
            await pilot.pause()
        value = box.value if cls is OsClipboardInput else box.text
        # Draw the box line by line the way the compositor does and render
        # each strip to the terminal sequence the driver would send.
        rendered = []
        for y in range(box.size.height):
            strip = box.render_line(y)
            rendered.append(strip.render(app.console))
        full = "".join(rendered)
        driver_out = "".join(writes)
    print(f"--- {cls.__name__} / {route}")
    print("  value repr:", repr(value))
    print("  driver.write calls:", len(writes), "bytes:", len(driver_out))
    for name, marker in MARKERS.items():
        in_value = marker.replace("]", "\x1b]", 1) in value if marker.startswith("]") else marker in value
        print(
            f"  {name:12s} in value={in_value!s:5s} "
            f"in rendered strip={marker in full!s:5s} "
            f"in driver output={marker in driver_out!s:5s}"
        )


async def main():
    for cls in (OsClipboardInput, CappedTextArea):
        for route in ("terminal paste", "ctrl+v app-clipboard fallback"):
            await run(cls, route)


asyncio.run(main())
