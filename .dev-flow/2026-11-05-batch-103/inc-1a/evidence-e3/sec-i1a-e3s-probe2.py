"""E3 security probe 2, batch-103 Inc 1a: the exact bytes the compositor would
send for a pasted ST-terminated OSC 52 and a CSI cursor move (headless, no
clipboard; the text is only rendered to a string, never written to a TTY)."""
import asyncio, os, sys
assert not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY")
import s19_app, textual
print("s19_app.__file__ =", s19_app.__file__, "textual =", textual.__version__)
from textual import events
from textual.app import App
from s19_app.tui.os_clipboard_input import OsClipboardInput
PAYLOAD = "C:/fw/good.s19\x1b[13D\x1b[0Kevil.s19\x1b]52;c;SElKQUNL\x1b\X"
class OneBox(App):
    def compose(self):
        yield OsClipboardInput(id="box")
async def main():
    app = OneBox()
    async with app.run_test(size=(100, 6)) as pilot:
        await pilot.click("#box"); await pilot.pause()
        app.post_message(events.Paste(PAYLOAD))
        for _ in range(4): await pilot.pause()
        box = app.query_one("#box")
        print("value repr :", repr(box.value))
        out = "".join(box.render_line(y).render(app.console) for y in range(box.size.height))
        i = out.find("good")
        print("render repr:", repr(out[max(0, i - 4): i + 80]))
        print("ST-terminated OSC 52 intact in render:", "\x1b]52;c;SElKQUNL\x1b\\" in out)
        print("CSI cursor-left 13 intact in render:", "\x1b[13D" in out)
asyncio.run(main())
