"""E3 round-3 security probe, batch-103 Inc 1a (<runner>, headless, no clipboard).

Question: does the round-2 correction (graph-inc1a.md at d6722b35) close
E3S-13 (strip order), E3S-14 (`restrict` boxes keep refusing), E3S-15 (the
strip set, `[Data: _UNSAFE_PASTE]`) and E3S-16 (oracles on the widget value),
and do round 1's P1/P2 shapes and the lone-surrogate / bidi shapes stay closed?

The base code (e07fb00) has no strip step, so the corrected design is
simulated by subclasses that do exactly what the nodes' `func:` say:
  C   = the corrected graph. `_UNSAFE_PASTE` is built with the literal
        expression of `[Data: _UNSAFE_PASTE]`; `_strip_paste_controls` as its
        node; `OsClipboardInput._on_paste`: cut, then (no `restrict`, text not
        empty) `event.text = strip(event.text.splitlines()[0], False)`;
        `OsClipboardInput.action_paste`: the base body without the Tk priming,
        the fallback cut, `line = text.splitlines()[0]` first, then strip when
        `restrict` is not set; `CappedTextArea._on_paste`: cut, then strip
        (multiline=True); `CappedTextArea.action_paste`: the base body without
        the priming, strip after the cut. The right-click route is the node's
        call of `action_paste` (`_on_mouse_down` -> this action).
  Negative controls of the rows: NoStrip (the base), SplitAfter (strip the
  whole text before the first-line split), C0C1 (a table without the
  surrogates and bidi controls), Bare (the bare `_CONTROL_SCRUB` in the
  multi-line box), StripRestrict (the strip applied to a `restrict` box too).

`[Data: _STRATEGIES]` is set to the corrected cascade (no tkinter). No
clipboard is opened: DISPLAY / WAYLAND_DISPLAY are unset (asserted), the OS
layers return None at once off Windows, and the headless driver writes to no
terminal. Paths under the host's home are printed as <home>.
"""
import asyncio
import io
import logging
import os
import re
import sys
import threading

assert not os.environ.get("DISPLAY"), "DISPLAY must be unset"
assert not os.environ.get("WAYLAND_DISPLAY"), "WAYLAND_DISPLAY must be unset"
assert sys.platform != "win32"
logging.disable(logging.WARNING)

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
from s19_app.tui.os_clipboard_input import OsClipboardInput  # noqa: E402
from s19_app.tui.capped_text_area import CappedTextArea  # noqa: E402

oci._STRATEGIES = tuple(s for s in oci._STRATEGIES if s[0] != "tkinter")  # [Data: _STRATEGIES] now
print("cascade =", [name for name, _ in oci._STRATEGIES])

CAP = oci._CLIPBOARD_CAP_CHARS
SGR = re.compile(r"\x1b\[[0-9;]*m")

# --- [Data: _UNSAFE_PASTE], the graph's literal expression -------------------
_UNSAFE_PASTE = dict.fromkeys((*_CONTROL_SCRUB, *range(0xD800, 0xE000), *range(0x202A, 0x202F), *range(0x2066, 0x206A)))
_UNSAFE_PASTE_SINGLE = {k: v for k, v in _UNSAFE_PASTE.items() if k != 0x09}
_UNSAFE_PASTE_MULTI = {k: v for k, v in _UNSAFE_PASTE.items() if k not in (0x09, 0x0A, 0x0D)}
# Negative-control tables.
C0C1_SINGLE = {k: None for k in _CONTROL_SCRUB if k != 0x09}
C0C1_MULTI = {k: None for k in _CONTROL_SCRUB if k not in (0x09, 0x0A, 0x0D)}
BARE = dict(_CONTROL_SCRUB)


def _strip_paste_controls(text: str, multiline: bool) -> str:
    return text.translate(_UNSAFE_PASTE_MULTI if multiline else _UNSAFE_PASTE_SINGLE)


def unsafe_left(s: str) -> list:
    return sorted({f"U+{ord(c):04X}" for c in s if ord(c) in _UNSAFE_PASTE_SINGLE})


# --- design C, single-line ---------------------------------------------------
class CInput(OsClipboardInput):
    TABLE = _UNSAFE_PASTE_SINGLE
    SPLIT_FIRST = True
    HONOUR_RESTRICT = True

    def _s(self, text):
        return text.translate(self.TABLE)

    def _on_paste(self, event: events.Paste) -> None:  # MRO: runs before Input._on_paste
        if len(event.text) > CAP:
            event.text = event.text[:CAP]
        if (not self.restrict or not self.HONOUR_RESTRICT) and event.text:
            if self.SPLIT_FIRST:
                event.text = self._s(event.text.splitlines()[0])
            else:
                event.text = self._s(event.text)

    async def action_paste(self) -> None:
        loop = asyncio.get_running_loop()
        text = await loop.run_in_executor(None, oci.read_os_clipboard)
        if text is None:
            text = self.app.clipboard[:CAP]
        if not text:
            self.select_all()
            self.app.notify(oci._PASTE_FAIL_NOTIFICATION, severity="warning", timeout=6.0)
            return
        if self.SPLIT_FIRST:
            line = text.splitlines()[0]
            if not self.restrict or not self.HONOUR_RESTRICT:
                line = self._s(line)
        else:
            line = self._s(text) if (not self.restrict or not self.HONOUR_RESTRICT) else text
            line = line.splitlines()[0] if line else ""
        start, end = self.selection
        self.replace(line, start, end)


class SplitAfterInput(CInput):
    SPLIT_FIRST = False


class C0C1Input(CInput):
    TABLE = C0C1_SINGLE


class StripRestrictInput(CInput):
    HONOUR_RESTRICT = False


# --- design C, multi-line ----------------------------------------------------
class CArea(CappedTextArea):
    TABLE = _UNSAFE_PASTE_MULTI

    def _on_paste(self, event: events.Paste) -> None:  # MRO: then CappedTextArea, TextArea
        if len(event.text) > CAP:
            event.text = event.text[:CAP]
        event.text = event.text.translate(self.TABLE)

    async def action_paste(self) -> None:
        if self.read_only:
            return
        loop = asyncio.get_running_loop()
        text = await loop.run_in_executor(None, oci.read_os_clipboard)
        if text is None:
            text = self.app.clipboard
        if not text:
            self.select_all()
            self.app.notify(oci._PASTE_FAIL_NOTIFICATION, severity="warning", timeout=6.0)
            return
        if len(text) > CAP:
            text = text[:CAP]
        text = text.translate(self.TABLE)
        if result := self._replace_via_keyboard(text, *self.selection):
            self.move_cursor(result.end_location)


class C0C1Area(CArea):
    TABLE = C0C1_MULTI


class BareArea(CArea):
    TABLE = BARE


class OneBox(App):
    def __init__(self, cls, **kw):
        super().__init__()
        self._cls, self._kw = cls, kw

    def compose(self) -> ComposeResult:
        yield Button("other", id="other")
        yield self._cls(id="box", **self._kw)


def is_area(box):
    return isinstance(box, CappedTextArea)


async def paste(cls, route, payload, start="", cursor=None, sel=False, **kw):
    """route: terminal (posted to the App, as the driver posts it) | ctrlv (the
    app-clipboard fallback, no OS clipboard) | right (the node's call of
    action_paste, as `_on_mouse_down` makes it)."""
    app = OneBox(cls, **kw)
    async with app.run_test(size=(120, 20)) as pilot:
        box = app.query_one("#box")
        box.focus()
        await pilot.pause()
        if start:
            if is_area(box):
                box.text = start
                box.move_cursor(cursor if cursor is not None else (0, len(start)))
            else:
                box.value = start
                box.cursor_position = cursor if cursor is not None else len(start)
            if sel:
                box.select_all()
            await pilot.pause()
        if route == "terminal":
            app.post_message(events.Paste(payload))
        elif route == "ctrlv":
            app._clipboard = payload
            await pilot.press("ctrl+v")
        else:
            app._clipboard = payload
            await box.action_paste()
        for _ in range(4):
            await pilot.pause()
        value = box.document.lines if is_area(box) else box.value
        drawn = "".join(box.render_line(y).render(app.console) for y in range(box.size.height))
    return value, drawn


ROUTES = ("terminal", "ctrlv", "right")
P_CTRL = "A\x1b[13DB\x00C\u202e\ud800"
P_CTRL_L = "L1\x1b[2J\nL2"
P_CTRL_M = "A\x1b[13DB\x00C\tD\r\nE\u202e\ud800"
P2_ESC = "L1 \u00d1\u20ac\x1b[2J\nL2 \u6f22"
LOAD = dict(restrict=r"[^\x00-\x1f\x7f]*", max_length=4096)  # screens.py:401-406
# Round 1's P1 / P2 shapes (+ C1 CSI, + lone surrogate, + bidi).
R1_P1 = ("A" + "\x1b]0;PWNED-TITLE\x07" + "B" + "\x1b]52;c;SElKQUNL\x07" + "C\x00D\u202eE"
         + "\x1b[5;31mBLINK" + "F\u2066G" + "\x9b31mH" + "\ud800I")
R1_P2 = "C:/fw/good.s19\x1b[13D\x1b[0Kevil.s19\x1b]52;c;SElKQUNL\x1b\\X"


def verdict(got, want):
    return "ok " if got == want else "BAD"


async def main():
    results = {}

    print("\n== U1  [Data: _UNSAFE_PASTE] keys (graph example)")
    for cp in (0xD800, 0xDFFF, 0x202E, 0x2069, 0x1B, 0x9B, 0x00, 0x7F, 0x09, 0x0A, 0x0D, 0xA0, 0x200F):
        print(f"  U+{cp:04X} single={cp in _UNSAFE_PASTE_SINGLE!s:5} multi={cp in _UNSAFE_PASTE_MULTI!s:5}")
    print("  key types:", sorted({type(k).__name__ for k in _UNSAFE_PASTE}), "size", len(_UNSAFE_PASTE))
    print("  strip(P-CTRL, single) =", repr(_strip_paste_controls(P_CTRL, False)))
    print("  strip(P-CTRL-M, multi) =", repr(_strip_paste_controls(P_CTRL_M, True)))
    print("  strip(P1 unicode) unchanged:", _strip_paste_controls("COPY-1 \u00d1o\u00f1o \u0416 \u6f22\u5b57 \U0001F600", False) == "COPY-1 \u00d1o\u00f1o \u0416 \u6f22\u5b57 \U0001F600")

    print("\n== S1  E3S-13/-16: single-line, design C, value oracles (R-PASTE.34/1-/4, R-PASTE.1, R-TUI-043.4)")
    cases = [
        ("P-CTRL", P_CTRL, "", None, "A[13DBC"),
        ("P-CTRL-L", P_CTRL_L, "", None, "L1[2J"),
        ("L1\\nL2", "L1\nL2", "", None, "L1"),
        ("unicode\\nsecond", "\u00d1o\u00f1o \u0416 \u6f22\u5b57 \U0001F600\nsecond", "", None, "\u00d1o\u00f1o \u0416 \u6f22\u5b57 \U0001F600"),
        ("ab|P1 line\\nsecond", "P1 line\nsecond", "ab", 1, "aP1 lineb"),
    ]
    for label, payload, start, cur, want in cases:
        for route in ROUTES:
            if label == "L1\\nL2" and route != "terminal":
                continue
            value, _ = await paste(CInput, route, payload, start=start, cursor=cur)
            print(f"  {verdict(value, want)} {label:20s} {route:8s} value={value!r} unsafe-left={unsafe_left(value)}")
            results.setdefault("S1", []).append(value == want)

    print("\n== S2  E3S-13/-15 negative controls, single-line (each must differ from the row)")
    for cls, label, payload, route, want_red in (
        (SplitAfterInput, "strip before split", P_CTRL_L, "terminal", "L1[2JL2"),
        (SplitAfterInput, "strip before split", P_CTRL_L, "ctrlv", "L1[2JL2"),
        (SplitAfterInput, "strip before split", "P1 line\nsecond", "ctrlv", "P1 linesecond"),
        (C0C1Input, "C0/C1-only table", P_CTRL, "terminal", "A[13DBC\u202e\ud800"),
        (OsClipboardInput, "no strip (base)", P_CTRL, "terminal", "A\x1b[13DB\x00C\u202e\ud800"),
    ):
        value, _ = await paste(cls, route, payload)
        print(f"  {'RED' if value == want_red else 'BAD'} {label:20s} {route:8s} value={value!r}")
        results.setdefault("S2", []).append(value == want_red)

    print("\n== M1  E3S-13/-16: multi-line, design C, document-line oracles (R-PASTE.35/1-/4, R-TUI-044.3)")
    for label, payload, start, cur, want in (
        ("P-CTRL-M", P_CTRL_M, "", None, ["A[13DBC\tD", "E"]),
        ("P2-ESC", P2_ESC, "", None, ["L1 \u00d1\u20ac[2J", "L2 \u6f22"]),
        ("ab|P1 line\\nsecond", "P1 line\nsecond", "ab", (0, 1), ["aP1 line", "secondb"]),
    ):
        for route in ROUTES:
            value, _ = await paste(CArea, route, payload, start=start, cursor=cur)
            print(f"  {verdict(value, want)} {label:20s} {route:8s} lines={value!r} unsafe-left={unsafe_left(''.join(value))}")
            results.setdefault("M1", []).append(value == want)

    print("\n== M2  negative controls, multi-line")
    for cls, label, payload, route in (
        (BareArea, "bare _CONTROL_SCRUB", P_CTRL_M, "terminal"),
        (BareArea, "bare _CONTROL_SCRUB", "P1 line\nsecond", "ctrlv"),
        (C0C1Area, "C0/C1-only table", P_CTRL_M, "terminal"),
        (CappedTextArea, "no strip (base)", P_CTRL_M, "terminal"),
    ):
        value, _ = await paste(cls, route, payload)
        print(f"  {label:20s} {route:8s} lines={value!r} unsafe-left={unsafe_left(''.join(value))}")

    print("\n== L1  E3S-14: #load_path shape (restrict, max_length=4096), design C -> '' (R-PASTE.34/5, R-LOADDLG.20)")
    for payload in ("a\x00.s19", "a\x1b[2K.s19"):
        for route in ROUTES:
            value, _ = await paste(CInput, route, payload, **LOAD)
            print(f"  {verdict(value, '')} {payload!r:16s} {route:8s} value={value!r}")
            results.setdefault("L1", []).append(value == "")
    print("  negative control: StripRestrictInput (the strip before `restrict`)")
    for payload in ("a\x00.s19", "a\x1b[2K.s19"):
        for route in ("terminal", "ctrlv"):
            value, _ = await paste(StripRestrictInput, route, payload, **LOAD)
            print(f"  {'RED' if value != '' else 'BAD'} {payload!r:16s} {route:8s} value={value!r}")
    print("  clean path still lands:", (await paste(CInput, "terminal", "C:/fw/a.s19", **LOAD))[0])

    print("\n== L2  the path box's own filter, design C: what it lets through (base gap; R-PASTE.34 'Base' names C1 only)")
    for name, payload in (("C1 CSI", "a\x9b31m.s19"), ("lone surrogate", "a\ud800.s19"),
                          ("RLO bidi", "a\u202e91s.exe"), ("LRI bidi", "a\u2066b.s19")):
        for route in ("terminal", "ctrlv"):
            value, drawn = await paste(CInput, route, payload, **LOAD)
            rest = SGR.sub("", drawn)
            print(f"  {name:15s} {route:8s} inserted={value != ''!s:5} unsafe-left={unsafe_left(value)} in-drawn={bool(unsafe_left(rest))}")

    print("\n== D1  round 1's P1/P2 shapes, design C: the drawn line after removing SGR (the security property)")
    for cls in (CInput, CArea):
        for payload_name, payload in (("R1-P1", R1_P1), ("R1-P2", R1_P2)):
            for route in ROUTES:
                value, drawn = await paste(cls, route, payload)
                rest = SGR.sub("", drawn)
                v = "".join(value) if isinstance(value, list) else value
                print(f"  {cls.__name__:7s} {payload_name} {route:8s} ESC-left={chr(27) in rest!s:5} "
                      f"unsafe-in-drawn={unsafe_left(rest)} unsafe-in-value={unsafe_left(v)}")
                results.setdefault("D1", []).append(chr(27) not in rest and not unsafe_left(rest) and not unsafe_left(v))

    print("\n== W1  a lone surrogate drawn in the path box (design C) -> textual's WriterThread")
    value, drawn = await paste(CInput, "ctrlv", "ok\ud800ok", **LOAD)
    print("  #load_path value:", repr(value), "| lone surrogate in the drawn line:", "\ud800" in drawn)
    for errors in ("strict", "surrogateescape"):
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
        print(f"  errors={errors:16s} thread exception={caught or None} frame-3 written={'frame-3' in out}")
    value, drawn = await paste(CInput, "ctrlv", "ok\ud800ok")
    print("  a box without restrict, same payload: value", repr(value), "| surrogate drawn:", "\ud800" in drawn)

    print("\n== E1  edges of the corrected nodes")
    for cls, label, payload, start, route in (
        (CInput, "only unsafe, terminal, over 'ab' selected", "\x1b", "ab", "terminal"),
        (CInput, "only unsafe, ctrl+v, over 'ab' selected", "\ud800", "ab", "ctrlv"),
        (CInput, "'\\n' alone, terminal", "\n", "", "terminal"),
        (CInput, "'\\n' alone, ctrl+v", "\n", "", "ctrlv"),
        (CInput, "C1 NEL line break", "A\x85B", "", "terminal"),
        (CInput, "U+2028 line break", "A\u2028B", "", "ctrlv"),
        (CArea, "only unsafe, multi, terminal", "\x1b\ud800", "", "terminal"),
    ):
        try:
            v, _ = await paste(cls, route, payload, start=start, sel=bool(start))
            print(f"  {label:42s} -> {v!r}")
        except Exception as exc:  # report, never hide
            print(f"  {label:42s} -> EXCEPTION {type(exc).__name__}: {exc}")

    print("\n== SUMMARY")
    for k, v in results.items():
        print(f"  {k}: {sum(v)}/{len(v)} as the records say")


asyncio.run(main())
