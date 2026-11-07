"""E3 round-2 security probe 2, batch-103 Inc 1a (<runner>, headless, no clipboard).

Question: can the drawn-line oracle of cases R-PASTE.34/1 and R-PASTE.35/1
("the drawn box line holds no ESC"; graph examples: "0 code points of the
scrub set") pass for a correct implementation? The renderer adds its own SGR
style sequences, so the check must look for the payload's sequences instead.
Reuses design R of sec-r2-1a-probe.py (same folder).
"""
import asyncio
import os
import re
import sys

assert not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util  # noqa: E402

spec = importlib.util.spec_from_file_location("p1", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sec-r2-1a-probe.py"))
src = open(spec.origin, encoding="utf-8").read().replace("asyncio.run(main())", "")
ns: dict = {"__name__": "p1"}
exec(compile(src, spec.origin, "exec"), ns)

SGR = re.compile(r"\x1b\[[0-9;]*m")


async def main():
    for cls_name in ("OsClipboardInput", "RInput", "CappedTextArea", "RArea"):
        cls = ns[cls_name]
        for payload in ("abc", "A\x1b[13DB\x00C\u202e\ud800"):
            value, drawn = await ns["paste"](cls, "terminal", payload)
            rest = SGR.sub("", drawn)
            print(f"  {cls_name:16s} payload={payload!r:28s} value={value!r:22s} "
                  f"ESC in drawn={chr(27) in drawn!s:5} ESC after removing SGR={chr(27) in rest!s:5} "
                  f"CSI-13D in drawn={chr(27) + '[13D' in drawn!s}")


asyncio.run(main())
