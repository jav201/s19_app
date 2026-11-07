"""E3 round-2 security probe, batch-103 Inc 1a (cachyos-rtx, headless, no clipboard).

Question: does the corrected design of E3S-01 (graph-inc1a.md after the
correction pass, commit 15129b64) close round 1's P1/P2 shapes, and does it
keep the rows it touches (R-PASTE.1, R-TUI-043.4, R-TUI-044.3, R-LOADDLG.20)?

The base code (e07fb00) has no strip step, so each design is simulated by a
subclass that does exactly what a node's `func:` says:
  G  = the graph as written: OsClipboardInput._on_paste cuts, then strips with
       "C0 except TAB + C1" BEFORE the stock Input._on_paste takes the first
       line; OsClipboardInput.action_paste strips the read/fallback text with
       "the _CONTROL_SCRUB strip", then takes `text.splitlines()[0]`;
       CappedTextArea._on_paste strips "C0 except TAB/LF/CR + C1";
       CappedTextArea.action_paste applies "the _CONTROL_SCRUB strip". No node
       skips the strip for a box with `restrict`.
       GInputT1 / GAreaT2 = G with the _on_paste set also used in action_paste.
  R  = the order and set round 1 asked for: the first line is taken first,
       then the CTX-PASTE "control character" set (C0/C1 + lone surrogates +
       bidi controls) is stripped; a box with `restrict` refuses the whole
       paste when it holds one (R-LOADDLG.20: "leave the path box unchanged").
  base = OsClipboardInput / CappedTextArea at e07fb00, unchanged (control).

No clipboard is opened: DISPLAY / WAYLAND_DISPLAY are unset (asserted), the OS
layers return None at once off Windows, and the headless driver writes to no
terminal. Paths under the host's home are printed as <home>.
"""
import asyncio
import io
import os
import re
import sys
import threading

assert not os.environ.get("DISPLAY"), "DISPLAY must be unset"
assert not os.environ.get("WAYLAND_DISPLAY"), "WAYLAND_DISPLAY must be unset"
assert sys.platform != "win32"

import s19_app  # noqa: E402
import textual  # noqa: E402


def red(s: str) -> str:
    return re.sub(r"/home/[^/]+", "<home>", s)


print("s19_app.__file__ =", red(s19_app.__file__))
print("textual =", textual.__version__, "python =", sys.version.split()[0])

from textual import events  # noqa: E402
from textual.app import App, ComposeResult  # noqa: E402
from textual.drivers._writer_thread import WriterThread  # noqa: E402
from textual.widgets import Button  # noqa: E402

from s19_app.utils import _CONTROL_SCRUB  # noqa: E402
from s19_app.tui import os_clipboard_input as oci  # noqa: E402
from s19_app.tui.os_clipboard_input import OsClipboardInput, read_os_clipboard  # noqa: E402
from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402

CAP = 65_536
ESC = "\x1b"
CSI13D = "\x1b[13D"
OSC52ST = "\x1b]52;c;SElKQUNL\x1b\\"
C1CSI = "\x9b"
LONE = "\ud800"
# The graph's sets, as each node's func: words them.
G_SINGLE = {k: None for k in _CONTROL_SCRUB if k != 0x09}          # C0 except TAB; C1
G_MULTI = {k: None for k in _CONTROL_SCRUB if k not in (0x09, 0x0A, 0x0D)}
G_LITERAL = dict(_CONTROL_SCRUB)                                     # "the _CONTROL_SCRUB strip"
# The CTX-PASTE "control character" set of 01-requirements.md.
EXTRA = {**{k: None for k in range(0xD800, 0xE000)},
         **{k: None for k in range(0x202A, 0x202F)},
         **{k: None for k in range(0x2066, 0x206A)}}
CTX_SINGLE = {**G_SINGLE, **EXTRA}
CTX_MULTI = {**G_MULTI, **EXTRA}


def has_ctx_char(s: str) -> bool:
    return s != s.translate(CTX_SINGLE)


class GInput(OsClipboardInput):
    """Design G, single-line (graph as written)."""
    AP_TABLE = G_LITERAL

    def _on_paste(self, event: events.Paste) -> None:  # runs before Input._on_paste (MRO)
        if len(event.text) > CAP:
            event.text = event.text[:CAP]
        event.text = event.text.translate(G_SINGLE)

    async def action_paste(self) -> None:
        loop = asyncio.get_running_loop()
        text = await loop.run_in_executor(None, read_os_clipboard)
        if text is None:
            text = self.app.clipboard[:CAP]
        text = text.translate(self.AP_TABLE)
        if not text:
            self.app.notify("Clipboard read failed", severity="warning")
            return
        self.replace(text.splitlines()[0], *self.selection)


class GInputT1(GInput):
    AP_TABLE = G_SINGLE


class RInput(OsClipboardInput):
    """Design R, single-line (first line, then the CTX set; restrict refuses)."""

    def _clean(self, text: str):
        first = text[:CAP].splitlines()[0] if text else ""
        if self.restrict is not None and has_ctx_char(first):
            return None  # refused whole, box unchanged
        return first.translate(CTX_SINGLE)

    def _on_paste(self, event: events.Paste) -> None:
        cleaned = self._clean(event.text)
        event.text = cleaned or ""

    async def action_paste(self) -> None:
        loop = asyncio.get_running_loop()
        text = await loop.run_in_executor(None, read_os_clipboard)
        if text is None:
            text = self.app.clipboard[:CAP]
        cleaned = self._clean(text)
        if cleaned is None:
            self.restricted()
            return
        if not cleaned:
            self.app.notify("Clipboard read failed", severity="warning")
            return
        self.replace(cleaned, *self.selection)


class GArea(CappedTextArea):
    """Design G, multi-line: strip, then CappedTextArea._on_paste / TextArea._on_paste (MRO)."""
    AP_TABLE = G_LITERAL

    def _on_paste(self, event: events.Paste) -> None:
        event.text = event.text.translate(G_MULTI)

    async def action_paste(self) -> None:
        text = self.app.clipboard[:CAP].translate(self.AP_TABLE)  # Linux: no OS read
        if text:
            self.insert(text)


class GAreaT2(GArea):
    AP_TABLE = G_MULTI


class RArea(CappedTextArea):
    def _on_paste(self, event: events.Paste) -> None:
        event.text = event.text.translate(CTX_MULTI)

    async def action_paste(self) -> None:
        text = self.app.clipboard[:CAP].translate(CTX_MULTI)
        if text:
            self.insert(text)


class OneBox(App):
    def __init__(self, cls, **kw):
        super().__init__()
        self._cls, self._kw = cls, kw

    def compose(self) -> ComposeResult:
        yield Button("other", id="other")
        yield self._cls(id="box", **self._kw)


async def paste(cls, route, payload, **kw):
    app = OneBox(cls, **kw)
    async with app.run_test(size=(120, 20)) as pilot:
        await pilot.click("#box")
        await pilot.pause()
        box = app.query_one("#box")
        if route == "terminal":
            app.post_message(events.Paste(payload))
        else:  # ctrl+v with no OS clipboard -> the app clipboard fallback
            app._clipboard = payload
            await pilot.press("ctrl+v")
        for _ in range(4):
            await pilot.pause()
        value = box.value if isinstance(box, OsClipboardInput) else box.text
        drawn = "".join(box.render_line(y).render(app.console) for y in range(box.size.height))
    return value, drawn


P1 = ("A" + "\x1b]0;PWNED-TITLE\x07" + "B" + "\x1b]52;c;SElKQUNL\x07" + "C\x00D\u202eE"
      + "\x1b[5;31mBLINK" + "F\u2066G" + "\x9b31mH" + "\ud800I")
MARKERS = {
    "ESC": ESC,
    "NUL": "\x00",
    "C1-CSI": C1CSI,
    "RLO": "\u202e",
    "LRI": "\u2066",
    "U+D800": LONE,
}
P2 = "C:/fw/good.s19\x1b[13D\x1b[0Kevil.s19\x1b]52;c;SElKQUNL\x1b\\X"


async def main():
    print("\n== T1  round-1 P1 shape (+ C1 CSI, + lone surrogate): marker in value / in drawn line")
    for cls in (OsClipboardInput, GInput, RInput, CappedTextArea, GArea, RArea):
        for route in ("terminal", "fallback"):
            value, drawn = await paste(cls, route, P1)
            cells = "  ".join(f"{n}={m in value!s:5}/{m in drawn!s:5}" for n, m in MARKERS.items())
            print(f"  {cls.__name__:15s} {route:8s} {cells}")

    print("\n== T2  round-1 P2 shape (cursor-left, erase, ST-terminated OSC 52) in the drawn line")
    for cls in (OsClipboardInput, GInput, RInput):
        for route in ("terminal", "fallback"):
            value, drawn = await paste(cls, route, P2)
            a, b = CSI13D in drawn, OSC52ST in drawn
            print(f"  {cls.__name__:15s} {route:8s} CSI-13D={a!s:5} OSC52-ST={b!s:5} value={value!r}")

    print("\n== T3  R-PASTE.1: terminal paste 'L1\\nL2' into a single-line box (row: 'L1')")
    for cls in (OsClipboardInput, GInput, RInput):
        value, _ = await paste(cls, "terminal", "L1\nL2")
        print(f"  {cls.__name__:15s} value={value!r}")

    print("\n== T4  R-TUI-043.4 / R-PASTE.29 shape: ctrl+v of 'P1 line\\nsecond' (fallback), single-line (row: 'P1 line')")
    for cls in (OsClipboardInput, GInput, GInputT1, RInput):
        value, _ = await paste(cls, "fallback", "P1 line\nsecond")
        print(f"  {cls.__name__:15s} value={value!r}")

    print("\n== T5  R-TUI-044.3 / R-PASTE.30 shape: ctrl+v of 'P1 line\\nsecond', multi-line (row: the line end kept)")
    for cls in (CappedTextArea, GArea, GAreaT2, RArea):
        value, _ = await paste(cls, "fallback", "P1 line\nsecond")
        print(f"  {cls.__name__:15s} value={value!r}")

    print("\n== T6  #load_path shape (restrict=[^\\x00-\\x1f\\x7f]*, max_length=4096); R-LOADDLG.20: 'leave the path box text unchanged'")
    kw = dict(restrict=r"[^\x00-\x1f\x7f]*", max_length=4096)
    for payload in ("a\x00.s19", "a\x1b[2K.s19", "a\x9b31m.s19"):
        for cls in (OsClipboardInput, GInput, RInput):
            for route in ("terminal", "fallback"):
                value, drawn = await paste(cls, route, payload, **kw)
                c1 = C1CSI in drawn
                print(f"  {payload!r:16s} {cls.__name__:15s} {route:8s} value={value!r:14s} "
                      f"unchanged={value == ''!s:5} C1-CSI-in-drawn={c1!s}")

    print("\n== T7  P-CTRL of 02-test-cases.md ('scrubbed to ABC')")
    pctrl = "A\x1b[13DB\x00C\u202e\ud800"
    print("  graph single-line set :", repr(pctrl.translate(G_SINGLE)))
    print("  CTX-PASTE set         :", repr(pctrl.translate(CTX_SINGLE)))
    os_route = pctrl.split("\x00", 1)[0]  # CF_UNICODETEXT ends at the first NUL (the corrected _read_via_ctypes cuts there)
    print("  via the OS clipboard  :", repr(os_route), "->", repr(os_route.translate(CTX_SINGLE)))
    try:
        pctrl.encode("utf-8")
        print("  UTF-8 stdin encode    : ok")
    except UnicodeEncodeError as exc:
        print("  UTF-8 stdin encode    : UnicodeEncodeError:", exc.reason, "at", exc.start)

    print("\n== T8  a lone surrogate left on screen -> textual's WriterThread (the driver's only writer)")
    value, drawn = await paste(GInput, "fallback", "ok\ud800ok")
    print("  design G value:", repr(value), "| lone surrogate in the drawn line:", LONE in drawn)
    for errors in ("strict", "surrogateescape", "backslashreplace"):
        raw = io.BytesIO()
        f = io.TextIOWrapper(raw, encoding="utf-8", errors=errors, write_through=True)
        caught = []
        old = threading.excepthook
        threading.excepthook = lambda a: caught.append(a.exc_type.__name__)
        w = WriterThread(f)
        w.start()
        w.write("frame-1|")
        w.write(drawn)
        w.write("|frame-3")
        w._queue.put(None)
        w.join(timeout=2)
        threading.excepthook = old
        out = raw.getvalue().decode("utf-8", "replace")
        print(f"  errors={errors:16s} thread exception={caught or None}  "
              f"thread alive={w.is_alive()}  frame-3 written={'frame-3' in out}")

    print("\n== T9  App.copy_to_clipboard of a lone surrogate (the copy tail's first call)")
    app = OneBox(OsClipboardInput)
    async with app.run_test(size=(80, 10)):
        try:
            App.copy_to_clipboard(app, "x\ud800")
            print("  no exception")
        except UnicodeEncodeError as exc:
            print("  UnicodeEncodeError:", exc.reason)

    print("\n== T10 the cascade tuples are read at call time (the E3S-02 conftest stand-ins can replace them)")
    print("  read_os_clipboard names _STRATEGIES:", "_STRATEGIES" in read_os_clipboard.__code__.co_names,
          "| write_os_clipboard names _WRITE_STRATEGIES:",
          "_WRITE_STRATEGIES" in oci.write_os_clipboard.__code__.co_names)


asyncio.run(main())
