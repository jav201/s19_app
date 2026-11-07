"""Inc 1a E1 pilot 3: terminal paste injected the way the driver does it (to the App).

i1a-pilot.py P6 posted `events.Paste` straight to the widget. For a TextArea that event
bubbles up to the App unforwarded, and `App.on_event` forwards it back to the focused box,
so it was inserted twice ('L1\\nL2L1\\nL2', 131,072 characters): an artifact of the
injection, not of the product. Here the Paste goes to the App, as the terminal driver posts
it, and the App forwards it once to the focused box. Same safety as pilot 1: no display, no
OS clipboard reachable, headless driver.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

import s19_app

print(f"s19_app.__file__ = {s19_app.__file__}")
print(f"python = {sys.version.split()[0]}; platform = {sys.platform}; DISPLAY={os.environ.get('DISPLAY')!r}")
assert not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"), "refusing: a display is set"

from textual import events  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402

from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402
from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402


class Probe(App):
    def compose(self) -> ComposeResult:
        yield OsClipboardInput(id="one")
        yield CappedTextArea(id="many")


def content(w) -> str:
    return w.value if isinstance(w, OsClipboardInput) else w.text


async def main() -> None:
    app = Probe()
    async with app.run_test(size=(100, 30)) as pilot:
        await pilot.pause()
        for payload, label in (("L1\nL2", "'L1\\nL2'"), ("x" * 70000, "70,000 chars"), ("Ñoño Ж 漢字 😀\nsecond", "non-ASCII two lines")):
            for wid in ("one", "many"):
                w = app.query_one(f"#{wid}")
                if wid == "one":
                    w.value = ""
                else:
                    w.text = ""
                w.focus()
                await pilot.pause()
                t0 = time.perf_counter()
                app.post_message(events.Paste(payload))
                for _ in range(5):
                    await pilot.pause()
                got = content(w)
                shown = repr(got) if len(got) < 60 else f"length {len(got)}"
                print(f"  terminal paste {label:<20} -> {type(w).__name__:<17}: {shown} ({(time.perf_counter()-t0)*1000:.1f} ms incl. 5 pauses)")
        # with a selection: replace it
        one = app.query_one("#one")
        one.value = "AAAA-BBBB"
        one.focus()
        await pilot.pause()
        one.selection = (0, 4)
        app.post_message(events.Paste("ZZ"))
        for _ in range(3):
            await pilot.pause()
        print(f"  terminal paste 'ZZ' over selection 'AAAA' in OsClipboardInput: {one.value!r}")
        many = app.query_one("#many")
        many.text = "AAAA-BBBB"
        many.focus()
        await pilot.pause()
        many.selection = ((0, 0), (0, 4))
        app.post_message(events.Paste("ZZ"))
        for _ in range(3):
            await pilot.pause()
        print(f"  terminal paste 'ZZ' over selection 'AAAA' in CappedTextArea : {many.text!r}")


asyncio.run(main())
print("\npilot3 done")
