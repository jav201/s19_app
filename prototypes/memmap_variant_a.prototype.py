"""Headless terminal captures for the Memory Map redesign variants.

Throwaway prototype (scratchpad, not repo). Renders each proposed variant as a
real Textual screen with the project's band palette/glyphs and exports an SVG
capture at 120x30 — the same convention as prototypes/legend_n8.variant_*.svg.

Run:  python mm_variants.py            -> writes mm_variant_{a,b,c}.120w.svg
"""

import asyncio

from rich.text import Text
from textual.app import App, ComposeResult
from textual.widgets import Static

# Real project tokens (styles.tcss / entropy_style.py, origin/main @ f8747b8)
CONST = "#6b7280"
LOW = "#5fb98a"
MED = "#d9a35b"
HIGH = "#e06c75"
GAP = "#3a4152"
FG = "#c9d1d9"
DIM = "#8b93a7"
FAINT = "#525b70"
ACCENT = "#7aa2f7"
BG = "#0b0f1a"
SEL_BG = "#2a3452"
TITLE = "bold #c9d1d9"


def t(*segments) -> Text:
    """Build a Text from (string, style) pairs; plain strings use FG."""
    out = Text()
    for seg in segments:
        if isinstance(seg, str):
            out.append(seg, style=FG)
        else:
            s, style = seg
            out.append(s, style=style)
    return out


class CaptureApp(App):
    CSS = f"""
    Screen {{ background: {BG}; }}
    #body {{ padding: 1 2; width: 100%; height: auto; }}
    """

    def __init__(self, lines):
        super().__init__()
        self._lines = lines

    def compose(self) -> ComposeResult:
        content = Text()
        for i, line in enumerate(self._lines):
            if i:
                content.append("\n")
            content.append_text(line)
        yield Static(content, id="body")


# --------------------------------------------------------------------------
# Variant A — gap-fold band bar
# --------------------------------------------------------------------------

def variant_a():
    L = []
    L.append(t(("Memory Map — Variant A · gap-fold band bar", TITLE)))
    L.append(t(""))
    L.append(t(
        "Entropy bands · 5 regions · ", ("1.0 KiB mapped", "bold " + FG),
        " · span 128.0 MiB · 4 gaps (", ("╱", GAP), (" = folded)", DIM),
    ))
    L.append(t(
        ("░", LOW), ("╱╱", GAP), ("▒" * 13, MED), ("╱", GAP),
        ("▒" * 13, MED), ("╱", GAP), ("▓" * 13, HIGH), ("╱", GAP),
        ("▒" * 13, MED),
    ))
    L.append(t(
        ("│", DIM), ("128M", FAINT), ("│08000000     ", DIM),
        ("│08000200      ", DIM), ("│08000400      ", DIM),
        ("│08000600 ─ 08000700", DIM),
    ))
    L.append(t(""))

    rows = [
        ("░", LOW, "0x00000000", "   6 B", "▏   ", "0", "low         ", True),
        ("▒", MED, "0x08000000", " 256 B", "████", "8", "medium      ", False),
        ("▒", MED, "0x08000200", " 256 B", "████", "0", "medium      ", False),
        ("▓", HIGH, "0x08000400", " 256 B", "████", "0", "high/random ", False),
        ("▒", MED, "0x08000600", " 256 B", "████", "0", "medium      ", False),
    ]
    inspector = [
        [("Inspector ", TITLE), ("(auto-selected)", DIM)],
        [("Status: ", DIM), ("VALID", "bold " + LOW)],
        [("Region: ", DIM), ("0x00000000-0x00000005 · 6 B", FG)],
        [("Band:   ", DIM), ("░ low", LOW), (" — structured / tables", DIM)],
        [("Peek @ 0x00000000:", DIM)],
        [("00000000  48 65 6C 6C 6F 21     Hello!", FAINT)],
    ]
    for i in range(max(len(rows), len(inspector))):
        if i < len(rows):
            g, col, addr, size, bar, sym, band, selected = rows[i]
            row_style = col + (" on " + SEL_BG if selected else "")
            line = t(
                (g + " ", row_style), (addr, row_style), (size + " ", row_style),
                (bar + " ", row_style), (sym + " sym ", row_style),
                (band, row_style), ("↵", row_style),
            )
        else:
            line = Text()
        pad = 52 - line.cell_len
        line.append(" " * max(1, pad))
        if i < len(inspector):
            line.append("┃ ", style=GAP)
            for s, style in inspector[i]:
                line.append(s, style=style)
        L.append(line)
    L.append(t(""))
    L.append(t((
        "Mapped 1.0 KiB / 128.0 MiB span (0.0008%) · 5 ranges (5 valid) · "
        "4 gaps (largest 128.0 MiB) · 32 issues", DIM)))
    L.append(t(""))
    L.append(t(
        ("↑↓", ACCENT), (" select  ", DIM), ("Enter", ACCENT),
        (" inspect  ", DIM), ("o", ACCENT), (" open hex  ", DIM),
        ("k", ACCENT), (" legend ░▒▓", DIM),
    ))
    return L


# --------------------------------------------------------------------------
# Variant B — two-lane map with linked cursor
# --------------------------------------------------------------------------

def variant_b():
    L = []
    L.append(t(("Memory Map — Variant B · two-lane map, linked cursor", TITLE)))
    L.append(t(""))
    L.append(t(
        ("SPAN     ", DIM), ("00000000 ", DIM),
        ("─" * 44, GAP), (" 08000700", DIM),
    ))
    L.append(t(("         ", DIM), ("╱" * 61, GAP), ("▓", "bold " + HIGH)))
    L.append(t(
        (" " * 68, DIM), ("╰┬╯ ", ACCENT), ("you are here", ACCENT),
    ))
    L.append(t(""))
    L.append(t(("PAYLOAD  ", DIM), ("mapped bytes only", DIM)))
    band = t(("         ", DIM))
    band.append("░", style=LOW)
    band.append(" ")
    band.append("▒" * 12, style=MED)
    band.append(" ")
    band.append("▒" * 12, style=MED)
    band.append(" ")
    band.append("▓" * 12, style="bold " + HIGH + " on " + SEL_BG)
    band.append(" ")
    band.append("▒" * 12, style=MED)
    L.append(band)
    prof = t(("         ", DIM))
    prof.append("▁", style=LOW)
    prof.append(" ")
    prof.append("▃▄▃▃▅▄▃▃▄▃▃▄", style=MED)
    prof.append(" ")
    prof.append("▄▃▃▄▄▃▅▃▃▄▃▃", style=MED)
    prof.append(" ")
    prof.append("▇█▇▇█▇▇██▇▇█", style=HIGH + " on " + SEL_BG)
    prof.append(" ")
    prof.append("▄▃▄▃▃▅▃▄▃▃▄▃", style=MED)
    L.append(prof)
    L.append(t(
        ("         6B ", DIM), ("08000000     ", DIM), ("08000200     ", DIM),
        ("►08000400", "bold " + ACCENT), ("    08000600", DIM),
    ))
    L.append(t(""))
    L.append(t(
        ("0x08000400 · 256 B · ", "bold " + FG), ("▓ high/random", HIGH),
        (" · 0 sym · 0 issues", "bold " + FG),
    ))
    L.append(t((
        "00000400  7F E3 91 0A C4 5D 22 B8   .....].\"    entropy 7.9/8.0",
        FAINT)))
    L.append(t(""))
    L.append(t(
        ("←/→ j/k", ACCENT), (" select  ", DIM), ("Enter", ACCENT),
        (" open hex  ", DIM), ("i", ACCENT), (" inspect  ", DIM),
        ("k", ACCENT), (" legend ░▒▓", DIM),
    ))
    return L


# --------------------------------------------------------------------------
# Variant C — inspector-led region table
# --------------------------------------------------------------------------

def variant_c():
    L = []
    L.append(t(("Memory Map — Variant C · inspector-led region table", TITLE)))
    L.append(t(""))
    L.append(t(
        ("░", LOW), ("╱╱", GAP), ("▒" * 14, MED), ("╱", GAP),
        ("▒" * 14, MED), ("╱", GAP), ("▓" * 14, HIGH), ("╱", GAP),
        ("▒" * 14, MED),
    ))
    L.append(t(""))
    L.append(t((
        "  BAND           START        SIZE  SIZE(log)  SYM  PROFILE", DIM)))
    table = [
        ("░ low         ", LOW, "0x00000000", "   6 B", "▎    ", "0", "▁   ", True),
        ("▒ medium      ", MED, "0x08000000", " 256 B", "█████", "8", "▃▄▃▅", False),
        ("▒ medium      ", MED, "0x08000200", " 256 B", "█████", "0", "▄▃▅▃", False),
        ("▓ high/random ", HIGH, "0x08000400", " 256 B", "█████", "0", "▇█▇█", False),
        ("▒ medium      ", MED, "0x08000600", " 256 B", "█████", "0", "▄▃▄▅", False),
    ]
    for band, col, addr, size, bar, sym, profile, selected in table:
        style = col + (" on " + SEL_BG if selected else "")
        L.append(t(
            ("  " if not selected else "▸ ", ACCENT if selected else DIM),
            (band, style), ("  " + addr, style), (size, style),
            ("  " + bar, style), ("      " + sym, style),
            ("   " + profile, style),
        ))
    L.append(t(""))
    L.append(t(
        ("Inspector — ", TITLE), ("0x00000000 · 6 B · ", FG),
        ("░ low", LOW), (" · 0 sym · VALID", FG),
    ))
    L.append(t(("00000000  48 65 6C 6C 6F 21     Hello!", FAINT)))
    L.append(t(""))
    L.append(t(
        ("↑↓", ACCENT), (" select  ", DIM), ("Enter", ACCENT),
        (" open hex  ", DIM), ("k", ACCENT), (" legend ░▒▓", DIM),
    ))
    return L


async def capture(name, lines, width=120, height=18):
    app = CaptureApp(lines)
    async with app.run_test(size=(width, height)) as pilot:
        await pilot.pause()
        svg = app.export_screenshot(title=f"s19tui — Memory Map · {name}")
    path = f"mm_variant_{name}.{width}w.svg"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(svg)
    print(f"wrote {path}")


async def main():
    await capture("A", variant_a())
    await capture("B", variant_b())
    await capture("C", variant_c())


if __name__ == "__main__":
    asyncio.run(main())
