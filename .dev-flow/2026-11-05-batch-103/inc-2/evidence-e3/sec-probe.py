# E3 security probe, Inc 2 batch-103: stdlib + textual only, no s19_app import.
import sys, struct, math
print("python", sys.version.split()[0])
def tryit(label, fn):
    try:
        print(label, "->", repr(fn()))
    except Exception as exc:
        print(label, "-> RAISES", type(exc).__name__, str(exc)[:80])
tryit("[S1] int('1'*5000)", lambda: int("1"*5000))
tryit("[S1] int('0x'+'f'*5000, 0) bit_length", lambda: int("0x"+"f"*5000, 0).bit_length())
tryit("[S2] int(float('1e400'))", lambda: int(float("1e400")))
tryit("[S2] int(float('nan'))", lambda: int(float("nan")))
tryit("[S3] float('1e400')", lambda: float("1e400"))
tryit("[S3] float('\uff11\uff12') fullwidth", lambda: float("\uff11\uff12"))
tryit("[S3] ' \t5\n'.strip()", lambda: " \t5\n".strip())
tryit("[S3] struct.pack('<f', inf)", lambda: struct.pack("<f", float("inf")).hex())
tryit("[S4] round(float(9007199254740993))", lambda: round(float(9007199254740993)))
tryit("[S5] %.6g 1.0000001 vs 1.0000009536743164", lambda: ("%.6g" % 1.0000001, "%.6g" % ((1.0000001 - 1e10) + 1e10), (1.0000001 - 1e10) + 1e10))
tryit("[S6] nan comparisons (x<nan, x>nan)", lambda: (5 < float("nan"), 5 > float("nan")))
import textual
print("textual", textual.__version__ if hasattr(textual, "__version__") else "?")
from textual.content import Content
tryit("[T1] Content.from_markup('[/x] closing only')", lambda: Content.from_markup("A[/x]B").plain)
tryit("[T2] Content.from_markup('[@click=app.quit]OFF[/]') spans", lambda: [str(s.style) for s in Content.from_markup("[@click=app.quit]OFF[/]").spans])
tryit("[T3] Content.from_markup('Map[b]x') plain", lambda: Content.from_markup("Map[b]x").plain)
tryit("[T4] Content('a\x1b[2Jb') plain repr", lambda: Content("a\x1b[2Jb").plain)
from rich.text import Text
tryit("[T5] rich Text('a\x1b[2Jb\x07') plain", lambda: Text("a\x1b[2Jb\x07").plain)
