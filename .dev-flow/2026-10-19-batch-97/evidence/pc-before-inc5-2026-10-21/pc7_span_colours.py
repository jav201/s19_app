"""Throwaway spike (PC-7, before Inc-5): a ``span_colours`` probe that reads the
painted fg/bg from the compositor strips over a widget's region AND the colour
spans of ``widget.render()``, matched by hue distance with a tolerance.

Proves: a colour applied by CSS (a TCSS variable, a class rule) is invisible to
``render().spans`` and visible in the compositor strips.
Part A: a minimal Textual app (TCSS variable, class rule, text-opacity blend).
Part B: the real s19 tree at HEAD — ``#flow_wiring_notice`` painted by the
``.sev-warning`` class rule (``styles.tcss`` ``#f6ff8f``) after a refused A2B Add.
"""
from __future__ import annotations
import asyncio, colorsys, sys, tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

REPO = Path(r"C:\Users\jjgh8\Github\s19_app")
sys.path.insert(0, str(REPO))

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Static, Button, Select


# ----------------------------------------------------------------- the probe
HUE_TOLERANCE = 4.0          # degrees; CRC #c9562b vs waiting #e8ad3d = 23.0
MIN_SATURATION = 0.30        # below this a hue is noise (greys, DGRAY)


def _hex(color) -> Optional[str]:
    if color is None:
        return None
    trip = color.get_truecolor() if hasattr(color, "get_truecolor") else None
    return trip.hex if trip is not None else None


def _hsv(hex_color: str):
    r, g, b = (int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5))
    return colorsys.rgb_to_hsv(r, g, b)


def hue_distance(a: str, b: str) -> float:
    d = abs(_hsv(a)[0] - _hsv(b)[0]) * 360.0 % 360.0
    return min(d, 360.0 - d)


def hue_matches(hex_color: Optional[str], target: str, tol: float = HUE_TOLERANCE) -> bool:
    return bool(hex_color) and _hsv(hex_color)[1] >= MIN_SATURATION and hue_distance(hex_color, target) <= tol


@dataclass(frozen=True)
class ColourRun:
    source: str            # "strip" | "span"
    text: str
    fg: Optional[str]
    bg: Optional[str]
    bold: bool
    x: int = -1            # screen column (strip) / char offset (span)
    y: int = -1            # screen row (strip only)


def span_colours(app, widget, region=None) -> list:
    """Every coloured run painted over ``widget``: compositor strips first
    (what the terminal shows — CSS colour, class rules, blends included), then
    the colour spans of ``widget.render()`` when it is a ``Text`` (C-37)."""
    runs = []
    strips = app.screen._compositor.render_strips()
    region = widget.region if region is None else region
    for y in range(region.y, min(region.y + region.height, len(strips))):
        x = region.x
        for seg in strips[y].crop(region.x, region.x + region.width):
            if seg.text and seg.text.strip() and seg.style is not None:
                runs.append(ColourRun("strip", seg.text, _hex(seg.style.color),
                                      _hex(seg.style.bgcolor), bool(seg.style.bold), x, y))
            x += len(seg.text)
    rendered = widget.render()
    # Textual 8: Static.render() returns textual.content.Content (spans whose
    # style is a str or a textual Style), not rich Text — read both.
    from textual.content import Content
    from rich.style import Style as RichStyle
    if isinstance(rendered, (Text, Content)):
        plain = rendered.plain
        for span in rendered.spans:
            style = span.style
            if isinstance(style, str):
                style = RichStyle.parse(style)
            elif not isinstance(style, RichStyle):
                style = getattr(style, "rich_style", None) or RichStyle()
            runs.append(ColourRun("span", plain[span.start:span.end], _hex(style.color),
                                  _hex(style.bgcolor), bool(style.bold), span.start))
    return runs


def summary(runs, target):
    strip = [r for r in runs if r.source == "strip"]
    span = [r for r in runs if r.source == "span"]
    s_hit = [r for r in strip if hue_matches(r.fg, target)]
    p_hit = [r for r in span if hue_matches(r.fg, target)]
    fgs = sorted({r.fg for r in strip if r.fg})
    return (f"strip runs {len(strip)} fg {fgs} match {len(s_hit)} | "
            f"render().spans {len(span)} match {len(p_hit)}"
            + (f" | hue distance of painted fg to {target}: "
               + ", ".join(f"{f} {hue_distance(f, target):.2f}°" for f in fgs) if fgs else ""))


# ----------------------------------------------------------------- part A
CRC = "#c9562b"
WAIT = "#e8ad3d"


class Mini(App):
    CSS = f"""
    $crc-family: {CRC};
    Screen {{ background: #0a0e1b; }}
    #by_var {{ color: $crc-family; background: #0f1525; }}
    .crc-chip {{ color: $crc-family; }}
    #by_blend {{ color: $crc-family; text-opacity: 70%; background: #0f1525; }}
    """

    def compose(self) -> ComposeResult:
        yield Static("CRC  stamps a CRC", id="by_var")
        yield Static("CRC  class rule", id="by_class", classes="crc-chip")
        yield Static(Text("CRC  span style", style=CRC), id="by_span")
        yield Static("CRC  text-opacity 70%", id="by_blend")


async def part_a():
    app = Mini()
    async with app.run_test(size=(60, 8)) as pilot:
        await pilot.pause(); await pilot.pause()
        for wid in ("by_var", "by_class", "by_span", "by_blend"):
            w = app.query_one(f"#{wid}")
            print(f"A  #{wid:9s}: {summary(span_colours(app, w), CRC)}")
        # control: the waiting token must NOT match the CRC-painted runs
        w = app.query_one("#by_var")
        hits = [r for r in span_colours(app, w) if hue_matches(r.fg, WAIT)]
        print(f"A  control: #by_var runs matching WAITING {WAIT} within {HUE_TOLERANCE}°: {len(hits)}")


# ----------------------------------------------------------------- part B
async def part_b():
    from s19_app.tui.app import S19TuiApp
    from s19_app.tui import insight_style
    with tempfile.TemporaryDirectory(dir=".", ignore_cleanup_errors=True) as td:
        app = S19TuiApp(base_dir=Path(td))
        async with app.run_test(size=(118, 54)) as pilot:
            app.action_show_screen("flow")
            for _ in range(6):
                await pilot.pause()
            panel = app.query_one("FlowBuilderPanel")
            panel.query_one("#flow_kind", Select).value = "a2b"
            for _ in range(4):
                await pilot.pause()
            panel.query_one("#flow_add", Button).press()   # empty bindings -> refusal
            for _ in range(6):
                await pilot.pause()
            notice = panel.query_one("#flow_wiring_notice")
            print("B  notice text:", repr(str(notice.render())[:70]), "classes", sorted(notice.classes))
            print(f"B  #flow_wiring_notice vs .sev-warning {insight_style.YELLOW}: "
                  f"{summary(span_colours(app, notice), insight_style.YELLOW)}")


asyncio.run(part_a())
asyncio.run(part_b())
