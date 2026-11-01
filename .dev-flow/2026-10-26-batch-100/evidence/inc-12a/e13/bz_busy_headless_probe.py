"""Headless re-run probe for the bz-busy E13 capture (Inc 12a).

Runs ``tools/e13/run.py``'s ``build_app`` for ``bz-busy`` at one terminal
size and prints what a capture PNG would show — read off the compositor,
never off the PNG. Prints the ``#status_text`` value, the ``#progress_bar``
value, the status-log lines and the key bar's painted rows. The PNGs the
capture script produces are never viewed.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
assert (ROOT / "s19_app").is_dir(), ROOT
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "e13"))

import run as e13  # noqa: E402
from textual.widgets import Footer, ProgressBar  # noqa: E402


def painted_rows(app, region):
    strips = app.screen._compositor.render_strips()
    rows = []
    for y in range(region.y, min(region.y + region.height, len(strips))):
        strip = strips[y].crop(region.x, region.x + region.width)
        rows.append("".join(seg.text for seg in strip))
    return rows


def key_bar_rows(app):
    rows = list(app.query("#key_bar KeyRow"))
    if rows:
        return [painted_rows(app, row.region) for row in rows]
    return [painted_rows(app, footer.region) for footer in app.query(Footer)]


def main() -> None:
    size = (int(sys.argv[1]), int(sys.argv[2]))
    base = Path(sys.argv[3])
    base.mkdir(parents=True, exist_ok=True)
    os.chdir(base)
    lad = base / "lad"
    lad.mkdir(parents=True, exist_ok=True)
    os.environ["LOCALAPPDATA"] = str(lad)
    app = e13.build_app(base, "bz-busy", close=False)

    async def once():
        async with app.run_test(size=size) as pilot:
            await app.e13_ready.wait()
            await pilot.pause()
            bar = app.query_one("#progress_bar", ProgressBar)
            print("SIZE", size[0], "x", size[1], flush=True)
            print("status_text:", str(app.query_one("#status_text").render()), flush=True)
            print("progress_bar:", bar.progress, "/", bar.total, flush=True)
            print("log_lines:", list(app.log_lines), flush=True)
            for i, rows in enumerate(key_bar_rows(app)):
                for r in rows:
                    print(f"keybar row {i}:", repr(r.rstrip()), flush=True)
        sys.stdout.flush()
        os._exit(0)

    asyncio.run(once())


if __name__ == "__main__":
    main()
