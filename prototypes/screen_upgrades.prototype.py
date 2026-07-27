"""PROTOTYPE - THROWAWAY. Do not ship, do not import from production code.

Question (v2, after operator feedback): for EACH existing screen — Workspace,
A2L Explorer, MAC View, Memory Map, Issues Report — what does an in-place
upgrade look like at each EFFORT TIER, keeping the screen's CURRENT layout
skeleton and its presence, and only enriching the visual data-insight cues?

Grounded in:
  - Textual docs sweep: border_title/subtitle, keyline, hatch, Sparkline,
    Rich Text cells in DataTable, zebra + fixed columns, tooltips, theme vars.
  - dolphie (charles-001/dolphie): semantic pastel theme, muted-label/bright-
    value idiom, 3-step navy depth stack, threshold coloring, humanized
    numbers, hotkey superscripts in panel titles, density calibrated for a
    maximized terminal at small font (~240x75 cells).

Tiers (cumulative): EASY = markup/colors/border-titles only, zero layout code.
MID = easy + micro-visuals inside existing panes (bars, strips, detail card).
BIG = mid + one structural addition within the same screen.

Run:      python prototypes/screen_upgrades.prototype.py
Headless: python prototypes/screen_upgrades.prototype.py --check  (SVGs -> prototypes/out/)
Keys:     1-5 pick screen (same digits as the real rail) - [ / ] cycle tier - q quit.

Untrusted-input safety deferred to dev-flow (C-16/C-17). Read-only over examples/.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import DataTable, Label, Sparkline, Static

from s19_app.core import S19File
from s19_app.tui.a2l import extract_a2l_tags, parse_a2l_file
from s19_app.tui.mac import parse_mac_file
from s19_app.tui.services.entropy_service import compute_entropy
from s19_app.validation.engine import validate_artifact_consistency

# ------------------------------------------------------------------ dolphie-ish theme
LABEL = "#c5c7d2"
VALUE = "#e9e9e9"
GREEN = "#54efae"
YELLOW = "#f6ff8f"
RED = "#fd8383"
HILITE = "#91abec"
LBLUE = "#bbc8e8"
DGRAY = "#969aad"
PURPLE = "#b565f3"
CYAN = "#7dd3fc"

APP_BG = "#0a0e1b"
PANEL_BG = "#0f1525"
ODD_BG = "#131a2c"
BORDER = "#1b233a"

BAND_STYLE = {
    "constant/padding": DGRAY,
    "very-low": DGRAY,
    "low": LBLUE,
    "medium": YELLOW,
    "high/random": RED,
    "high": RED,
    "very-high": RED,
}
BAND_GLYPH = {"constant/padding": "░", "very-low": "░", "low": "▒", "medium": "▓",
              "high/random": "█", "high": "█", "very-high": "█"}

# ------------------------------------------------------------------ data (real)

S19_PATH = REPO / "examples" / "case_00_public" / "prg.s19"
A2L_PATH = REPO / "examples" / "case_00_public" / "ASAP2_Demo_V161.a2l"
MAC_PATH = REPO / "examples" / "case_00_public" / "synthetic_update_test1.mac"
BAD_S19_DIR = REPO / "examples" / "case_04_bad_checksums"


def load_world() -> dict:
    s19 = S19File(str(S19_PATH))
    mem = s19.get_memory_map()
    ranges = s19.get_memory_ranges()
    a2l = parse_a2l_file(A2L_PATH)
    tags = extract_a2l_tags(
        a2l["sections"], a2l.get("record_layouts_by_name"), a2l.get("compu_methods_by_name")
    )
    mac = parse_mac_file(MAC_PATH)
    report = validate_artifact_consistency(mac["records"], tags, a2l, ranges)
    entry = "—"
    for rec in s19.records:
        if rec.type in ("S7", "S8", "S9"):
            entry = f"0x{rec.address:08X}"
            break
    bad_errors: list[dict] = []
    for cand in sorted(BAD_S19_DIR.glob("*.s19")) if BAD_S19_DIR.exists() else []:
        errs = S19File(str(cand)).get_errors()
        if errs:
            bad_errors = errs
            break
    in_mem = sum(1 for t in tags if isinstance(t.get("address"), int) and t["address"] in mem)
    return {
        "mem": mem, "ranges": ranges, "size": len(mem), "endian": s19.endian,
        "entry": entry, "ooo": s19.get_out_of_order_records(), "tags": tags,
        "tags_in_mem": in_mem, "mac": mac, "report": report,
        "entropy": compute_entropy(mem), "bad_errors": bad_errors,
    }


# ------------------------------------------------------------------ helpers


def human(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / 1024 / 1024:.2f}MB"
    if n >= 1024:
        return f"{n / 1024:.2f}KB"
    return f"{n}B"


def lv(label: str, value: str, vstyle: str = VALUE) -> Text:
    t = Text()
    t.append(f"{label} ", style=LABEL)
    t.append(value, style=vstyle)
    return t


def pct_style(value: float, warn: float = 50.0, bad: float = 20.0) -> str:
    # coverage-style: high is good
    if value >= warn:
        return GREEN
    if value >= bad:
        return YELLOW
    return RED


def microbar(frac: float, width: int = 10, style: str = HILITE) -> Text:
    filled = max(0, min(width, round(frac * width)))
    t = Text()
    t.append("█" * filled, style=style)
    t.append("·" * (width - filled), style=BORDER)
    return t


def hex_dump(mem: dict, start: int, rows: int, tier: str) -> Text:
    out = Text()
    addr = start
    for _ in range(rows):
        vals = [mem.get(addr + i) for i in range(16)]
        out.append(f" 0x{addr:08X}  ", style=f"bold {CYAN}")
        for b in vals:
            if b is None:
                out.append("-- ", style=BORDER)
            elif tier == "easy":
                out.append(f"{b:02X} ", style=VALUE)
            elif b in (0x00, 0xFF):
                out.append(f"{b:02X} ", style=DGRAY)          # padding de-emphasized
            elif 32 <= b < 127:
                out.append(f"{b:02X} ", style=CYAN)           # printable
            else:
                out.append(f"{b:02X} ", style=VALUE)
        out.append(" ")
        asc = "".join("." if b is None or not 32 <= b < 127 else chr(b) for b in vals)
        out.append(f"|{asc}|", style=DGRAY)
        out.append("\n")
        addr += 16
    return out


def sev_counts(report) -> tuple[int, int, int]:
    e = w = i = 0
    for issue in report.issues:
        name = getattr(issue.severity, "name", "").upper()
        if "ERROR" in name:
            e += 1
        elif "WARN" in name:
            w += 1
        else:
            i += 1
    return e, w, i


# ------------------------------------------------------------------ current chrome (unchanged on purpose)

RAIL_ENTRIES = [("◫", "Workspace"), ("≡", "A2L Explorer"), ("◉", "MAC View"),
                ("▤", "Memory Map"), ("!", "Issues Report"), ("✎", "Patch Editor"),
                ("⏚", "A2B Diff"), ("✦", "Flow Builder")]


def build_rail(active: int) -> Vertical:
    rows = []
    for i, (glyph, name) in enumerate(RAIL_ENTRIES):
        cls = "rail-row" + (" rail-active" if i == active else "")
        rows.append(Static(f" {glyph}  {name}", classes=cls))
    return Vertical(*rows, classes="rail")


def command_bar(world: dict) -> Static:
    t = Text()
    t.append("› ", style=f"bold {HILITE}")
    t.append("Project: ", style=LABEL)
    t.append("(none)   ", style=VALUE)
    t.append("A2L: ", style=LABEL)
    t.append("ASAP2_Demo_V161.a2l   ", style=VALUE)
    t.append("[find                ] [goto 0xADDR        ]", style=DGRAY)
    return Static(t, classes="cmdbar")


def footer_bar() -> Static:
    t = Text(" ")
    for key, act in [("^k", "Palette"), ("^d", "Density"), ("^l", "Load"), ("^s", "Save"),
                     ("/", "Find"), ("g", "Go-to"), ("q", "Quit"), ("x", "Operations"),
                     ("k", "Legend"), ("+", "Page+"), ("-", "Page-")]:
        t.append(f" {key} ", style=f"bold {APP_BG} on {LBLUE}")
        t.append(f" {act} ", style=LABEL)
    return Static(t, classes="footbar")


# ------------------------------------------------------------------ SCREEN 1: WORKSPACE
# Skeleton preserved: memstrip / left(files+sections) / center(hex controls+hex) / right(stats+context)


class WorkspaceProto(Vertical):
    def __init__(self, world: dict, tier: str) -> None:
        super().__init__(classes="scrbody")
        self.world, self.tier = world, tier

    def _memstrip(self) -> Static:
        w, tier = self.world, self.tier
        t = Text()
        if tier == "easy":
            t.append("█" * 76, style=HILITE)
        else:
            total_span = w["ranges"][-1][1] - w["ranges"][0][0] or 1
            # MID+: strip colored by entropy band, hatch-style dots for gaps
            cells = 100
            for c in range(cells):
                a = w["ranges"][0][0] + int(total_span * c / cells)
                win = next((x for x in w["entropy"] if x.start <= a <= x.end), None)
                if win is None:
                    t.append("╱", style=BORDER)  # unmapped: hatch texture
                else:
                    t.append(BAND_GLYPH.get(win.band, "▒"), style=BAND_STYLE.get(win.band, LBLUE))
        s = Static(t, classes="memstrip")
        if self.tier != "easy":
            s.border_title = "image map — entropy"
            s.border_subtitle = "╱ unmapped"
        return s

    def _stat_boxes(self) -> Horizontal:
        # BIG tier only: dolphie-style stat boxes row (structural addition)
        w = self.world
        e, warn, _ = sev_counts(w["report"])

        def box(title: str, rows: list[tuple[str, Text | str]]) -> Static:
            tbl = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
            tbl.add_column(justify="right", style=LABEL, no_wrap=True)
            tbl.add_column(no_wrap=True)
            for k, v in rows:
                tbl.add_row(k, v)
            st = Static(tbl, classes="statbox")
            st.border_title = title
            return st

        cov = w["report"].coverage
        return Horizontal(
            box("¹Image", [
                ("file", Text("prg.s19", style=VALUE)),
                ("size", Text(f"{human(w['size'])} · {len(w['ranges'])} ranges", style=VALUE)),
                ("endian", Text(w["endian"], style=VALUE)),
                ("entry", Text(w["entry"], style=VALUE)),
            ]),
            box("Integrity", [
                ("loader", Text("0 errors", style=GREEN)),
                ("order", Text(f"{len(w['ooo'])} out-of-order", style=YELLOW)),
                ("checksums", Text("all valid", style=GREEN)),
            ]),
            box("Coverage", [
                ("MAC→S19", Text(f"{cov.mac_in_s19}/{cov.mac_total}", style=pct_style(0.0))),
                ("A2L→S19", Text(f"{cov.a2l_in_s19}/{cov.a2l_total}", style=pct_style(0.0))),
                ("A2L↔MAC", Text(f"{cov.a2l_mac_address_matches} match", style=VALUE)),
            ]),
            box("Issues", [
                ("errors", Text(str(e), style=f"bold {RED}")),
                ("warnings", Text(str(warn), style=YELLOW)),
                ("view", Text("5 ↵", style=HILITE)),
            ]),
            classes="statrow",
        )

    def compose(self) -> ComposeResult:
        w, tier = self.world, self.tier
        if tier == "big":
            yield self._stat_boxes()
        yield self._memstrip()
        with Horizontal(classes="body"):
            with Vertical(classes="pane wsleft"):
                yield Static(Text("Load project (p)", style=HILITE), classes="rowbtn")
                secs = Static(self._sections(), classes="fill")
                secs.border_title = "Data Sections"
                secs.border_subtitle = f"{len(w['ranges'])} ranges"
                yield secs
            with Vertical(classes="pane wscenter"):
                yield Static(Text("[Search ASCII    ] Find Next   [Goto 0xADDR  ] Goto",
                                  style=DGRAY), classes="rowbtn")
                hx = Static(hex_dump(w["mem"], w["ranges"][5][0] & ~0xF, 12, tier), classes="fill")
                hx.border_title = "Hex View"
                if tier != "easy":
                    hx.border_subtitle = "00/FF dim · ascii cyan"
                yield hx
            with Vertical(classes="pane wsright"):
                st = Static(self._stats(), classes="stats")
                st.border_title = "Coverage Stats"
                yield st
                ctx = Static(self._ctx_panel(), classes="fill")
                ctx.border_title = "Context"
                yield ctx

    def _sections(self) -> Text:
        w, tier = self.world, self.tier
        t = Text()
        biggest = max(b - a + 1 for a, b in w["ranges"])
        for a, b in w["ranges"]:
            size = b - a + 1
            t.append("✓ ", style=GREEN)
            t.append(f"0x{a:08X} ", style=CYAN)
            t.append(f"{human(size):>8} ", style=VALUE)
            if tier != "easy":
                t.append_text(microbar(size / biggest, 8))
                win = next((x for x in w["entropy"] if x.start <= a <= x.end), None)
                if win:
                    t.append(f" {BAND_GLYPH.get(win.band, '▒')}",
                             style=BAND_STYLE.get(win.band, LBLUE))
            t.append("\n")
        return t

    def _stats(self) -> Text:
        w, tier = self.world, self.tier
        e, warn, _ = sev_counts(w["report"])
        t = Text()
        cov_pct = 100.0 * w["tags_in_mem"] / (len(w["tags"]) or 1)
        t.append_text(lv("Coverage", f"{cov_pct:.2f}%", pct_style(cov_pct)))
        if tier != "easy":
            t.append("  ")
            t.append_text(microbar(cov_pct / 100, 8, pct_style(cov_pct)))
        t.append("\n")
        t.append_text(lv("Ranges", str(len(w["ranges"])))); t.append("\n")
        t.append_text(lv("Errors", "0", GREEN)); t.append("  ")
        t.append_text(lv("Warnings", str(warn), YELLOW if warn else GREEN)); t.append("\n")
        if tier != "easy":
            t.append_text(lv("Loader", "0 err", GREEN)); t.append(" ")
            t.append(f"⚠{len(w['ooo'])} OOO", style=YELLOW); t.append("\n")
            t.append_text(lv("Entry", w["entry"])); t.append("\n")
        return t

    def _ctx_panel(self) -> Text:
        t = Text()
        if self.tier == "easy":
            t.append("(select an address)", style=DGRAY)
        else:
            t.append("0x0000EB08", style=CYAN); t.append(" in ", style=LABEL)
            t.append("0xEB08–0xFA2E", style=VALUE); t.append("\n")
            t.append("band ", style=LABEL); t.append("medium ▓", style=YELLOW); t.append("\n")
            t.append("A2L ", style=LABEL); t.append("no symbol here", style=DGRAY)
        return t


# ------------------------------------------------------------------ SCREEN 2: A2L
# Skeleton preserved: left(filter row + tags table + summary) / right(hex [+ detail card in MID+])


class A2lProto(Vertical):
    def __init__(self, world: dict, tier: str) -> None:
        super().__init__(classes="scrbody")
        self.world, self.tier = world, tier

    def compose(self) -> ComposeResult:
        w, tier = self.world, self.tier
        with Horizontal(classes="body"):
            with Vertical(classes="pane a2lleft"):
                yield Static(Text("[Field: name ▾]  All  Invalid  In-Memory   [find tag     ] Find next",
                                  style=DGRAY), classes="rowbtn")
                table: DataTable = DataTable(zebra_stripes=True, cursor_type="row")
                yield table
                summary = Text()
                summary.append("Page ", style=LABEL); summary.append("1/1", style=VALUE)
                summary.append(" · tags ", style=LABEL); summary.append("1-32/75", style=VALUE)
                summary.append(" · in-image ", style=LABEL)
                summary.append(f"{w['tags_in_mem']}", style=RED if not w["tags_in_mem"] else GREEN)
                yield Static(summary, classes="rowbtn")
            with Vertical(classes="pane a2lright"):
                if tier != "easy":
                    card = Static(self._detail_card(), classes="detailcard")
                    card.border_title = "MEAS ASAM.M.SCALAR.UBYTE.IDENTICAL"
                    card.border_subtitle = "28 fields parsed"
                    yield card
                hx = Static(hex_dump(w["mem"], w["ranges"][5][0] & ~0xF,
                                     6 if tier != "easy" else 12, tier), classes="fill")
                hx.border_title = "Hex Viewer"
                yield hx

    def on_mount(self) -> None:
        w, tier = self.world, self.tier
        tbl = self.query_one(DataTable)
        if self.tier == "big":
            tbl.add_columns("", "Tag", "Address", "Len", "Type", "Unit", "Src", "Mem")
        else:
            tbl.add_columns("", "Tag", "Address", "Len", "Src", "Raw", "Phys", "Mem")
        for tag in w["tags"][:14]:
            addr = tag.get("address")
            in_mem = isinstance(addr, int) and addr in w["mem"]
            glyph = Text("✓", style=GREEN) if in_mem else Text("·", style=DGRAY)
            name = Text(str(tag["name"])[:26], style=VALUE)
            addr_t = Text(f"0x{addr:08X}" if isinstance(addr, int) else "—", style=CYAN)
            if self.tier == "big":
                row = (glyph, name, addr_t,
                       Text(str(tag.get("length") or "—"), style=VALUE, justify="right"),
                       Text(str(tag.get("datatype") or "—"), style=PURPLE),
                       Text(str(tag.get("unit") or "—"), style=LBLUE),
                       Text(str(tag.get("source") or ""), style=DGRAY),
                       Text("in-img" if in_mem else "no-hit", style=GREEN if in_mem else DGRAY))
            else:
                row = (glyph, name, addr_t,
                       Text(str(tag.get("length") or "—"), style=VALUE, justify="right"),
                       Text(str(tag.get("source") or ""), style=DGRAY),
                       Text("—", style=DGRAY), Text("—", style=DGRAY),
                       Text("yes" if in_mem else "no", style=GREEN if in_mem else DGRAY))
            tbl.add_row(*row)

    def _detail_card(self) -> Table:
        tag = next((t for t in self.world["tags"] if t.get("description")), self.world["tags"][0])
        tbl = Table(show_header=False, box=None, padding=(0, 1), pad_edge=False)
        tbl.add_column(justify="right", style=LABEL, no_wrap=True)
        tbl.add_column(style=VALUE)
        tbl.add_row("descr", Text(str(tag.get("description") or "—")[:48], style=VALUE))
        tbl.add_row("unit · conv", f"{tag.get('unit') or '—'} · {tag.get('conversion') or '—'}")
        tbl.add_row("layout", str(tag.get("record_layout_name") or tag.get("deposit") or "—"))
        tbl.add_row("byte order", str(tag.get("effective_byte_order") or "—"))
        tbl.add_row("limits", f"{tag.get('lower_limit')} … {tag.get('upper_limit')}")
        return tbl


# ------------------------------------------------------------------ SCREEN 3: MAC
# Skeleton preserved: left(records table + summary) / right(hex) [+ coverage strip in MID+]


class MacProto(Vertical):
    def __init__(self, world: dict, tier: str) -> None:
        super().__init__(classes="scrbody")
        self.world, self.tier = world, tier

    def compose(self) -> ComposeResult:
        w, tier = self.world, self.tier
        if tier != "easy":
            cov = w["report"].coverage
            strip = Text(" ")
            strip.append("MAC→S19 ", style=LABEL)
            strip.append(f"{cov.mac_in_s19} of {cov.mac_total} ", style=RED if not cov.mac_in_s19 else GREEN)
            strip.append_text(microbar(cov.mac_in_s19 / (cov.mac_total or 1), 14,
                                       RED if not cov.mac_in_s19 else GREEN))
            strip.append("   A2L↔MAC ", style=LABEL)
            strip.append(f"{cov.a2l_mac_address_matches} addr matches", style=VALUE)
            s = Static(strip, classes="covstrip")
            s.border_title = "coverage"
            yield s
        with Horizontal(classes="body"):
            with Vertical(classes="pane macleft"):
                table: DataTable = DataTable(zebra_stripes=True, cursor_type="row")
                yield table
                yield Static(Text("Page 1/1 · 10 records", style=DGRAY), classes="rowbtn")
            with Vertical(classes="pane macright"):
                hx = Static(hex_dump(w["mem"], w["ranges"][5][0] & ~0xF, 12, tier), classes="fill")
                hx.border_title = "Hex Viewer"
                yield hx

    def on_mount(self) -> None:
        w, tier = self.world, self.tier
        tbl = self.query_one(DataTable)
        cols = [" ", "Tag", "Address"]
        if tier == "big":
            cols += ["In-img", "Aliases"]
        tbl.add_columns(*cols)
        for rec in w["mac"]["records"][:12]:
            ok = rec.get("parse_ok", False)
            addr = rec.get("address")
            in_img = isinstance(addr, int) and addr in w["mem"]
            if not ok:
                glyph, gstyle = "✗", RED
            elif not in_img:
                glyph, gstyle = "⚠", YELLOW
            else:
                glyph, gstyle = "✓", GREEN
            row = [Text(glyph, style=f"bold {gstyle}"),
                   Text(str(rec.get("name"))[:24], style=VALUE if ok else RED),
                   Text(f"0x{addr:08X}" if isinstance(addr, int) else "—", style=CYAN)]
            if tier == "big":
                row.append(Text("yes" if in_img else "out-of-range",
                                style=GREEN if in_img else YELLOW))
                row.append(Text("—", style=DGRAY))
            tbl.add_row(*row)


# ------------------------------------------------------------------ SCREEN 4: MEMORY MAP
# Skeleton preserved: header line / band strip / (glance + hint) / region rows / stats


class MapProto(Vertical):
    def __init__(self, world: dict, tier: str) -> None:
        super().__init__(classes="scrbody")
        self.world, self.tier = world, tier

    def compose(self) -> ComposeResult:
        w, tier = self.world, self.tier
        head = Text()
        head.append("Entropy bands", style=f"bold {LBLUE}")
        head.append(f" — {len(w['entropy'])} regions · {human(w['size'])} mapped", style=LABEL)
        yield Static(head, classes="rowbtn")
        # proportional band strip (current concept, pastel + hatch gaps)
        strip = Text(" ")
        span = (w["ranges"][-1][1] - w["ranges"][0][0]) or 1
        for c in range(100):
            a = w["ranges"][0][0] + int(span * c / 100)
            win = next((x for x in w["entropy"] if x.start <= a <= x.end), None)
            if win is None:
                strip.append("╱", style=BORDER)
            else:
                strip.append(BAND_GLYPH.get(win.band, "▒"), style=BAND_STYLE.get(win.band, LBLUE))
        st = Static(strip, classes="memstrip")
        st.border_subtitle = "╱ unmapped"
        yield st
        if tier != "easy":
            ruler = Text(" ")
            for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
                a = w["ranges"][0][0] + int(span * frac)
                ruler.append(f"0x{a:06X}", style=DGRAY)
                if frac < 1.0:
                    ruler.append(" " * 17)
            yield Static(ruler, classes="rowbtn")
        with Horizontal(classes="body"):
            rows = Static(self._region_rows(), classes="fill pane")
            rows.border_title = "regions"
            rows.border_subtitle = "↵ open in hex" if tier != "easy" else ""
            yield rows
            with Vertical(classes="pane mapright"):
                gl = Static(self._glance(), classes="glance")
                gl.border_title = "At a glance"
                yield gl
                if tier == "big":
                    det = Static(self._detail(), classes="fill")
                    det.border_title = "region 0x0000EB08"
                    yield det
                else:
                    yield Static(Text("Click a region row to inspect it\nand jump to the hex view.",
                                      style=DGRAY), classes="fill")

    def _region_rows(self) -> Text:
        w, tier = self.world, self.tier
        t = Text()
        biggest = max((x.end - x.start + 1) for x in w["entropy"])
        for win in w["entropy"][:12]:
            size = win.end - win.start + 1
            t.append(f" {BAND_GLYPH.get(win.band, '▒')} ", style=BAND_STYLE.get(win.band, LBLUE))
            t.append(f"0x{win.start:08X} ", style=CYAN)
            t.append(f"{human(size):>9} ", style=VALUE)
            t.append(f"{win.band:<12}", style=BAND_STYLE.get(win.band, LBLUE))
            if tier != "easy":
                t.append_text(microbar(size / biggest, 10))
                nsym = sum(1 for g in w["tags"]
                           if isinstance(g.get("address"), int) and win.start <= g["address"] <= win.end)
                t.append(f"  {nsym} sym", style=HILITE if nsym else DGRAY)
                t.append("  ↵", style=HILITE)
            t.append("\n")
        return t

    def _glance(self) -> Text:
        w = self.world
        counts: dict[str, int] = {}
        for win in w["entropy"]:
            counts[win.band] = counts.get(win.band, 0) + 1
        total = sum(counts.values()) or 1
        t = Text()
        for band, n in counts.items():
            t.append(f"{BAND_GLYPH.get(band, '▒')} ", style=BAND_STYLE.get(band, LBLUE))
            t.append(f"{band:<14}", style=LABEL)
            t.append(f"{n:>2} ", style=VALUE)
            t.append_text(microbar(n / total, 6, BAND_STYLE.get(band, LBLUE)))
            t.append(f" {100 * n // total}%", style=DGRAY)
            t.append("\n")
        return t

    def _detail(self) -> Text:
        w = self.world
        win = max(w["entropy"], key=lambda x: x.end - x.start)
        t = Text()
        t.append_text(lv("span", f"0x{win.start:08X}–0x{win.end:08X}")); t.append("\n")
        t.append_text(lv("size", human(win.end - win.start + 1))); t.append("\n")
        t.append_text(lv("band", win.band, BAND_STYLE.get(win.band, LBLUE))); t.append("\n\n")
        t.append_text(hex_dump(w["mem"], win.start & ~0xF, 3, "mid"))
        return t


# ------------------------------------------------------------------ SCREEN 5: ISSUES
# Skeleton preserved: filter tabs row / grouped list left + hex right / summary line


class IssuesProto(Vertical):
    def __init__(self, world: dict, tier: str) -> None:
        super().__init__(classes="scrbody")
        self.world, self.tier = world, tier

    def compose(self) -> ComposeResult:
        w, tier = self.world, self.tier
        e, warn, info = sev_counts(w["report"])
        tabs = Text(" ")
        tabs.append("Issues: ", style=LABEL)
        tabs.append(f" All {e + warn + info} ", style=f"bold {APP_BG} on {LBLUE}")
        tabs.append("  ")
        tabs.append(f" Errors {e} ", style=f"bold {VALUE} on #5b2430")
        tabs.append("  ")
        tabs.append(f" Warnings {warn} ", style=f"bold {APP_BG} on {YELLOW}")
        tabs.append("   Legend", style=DGRAY)
        if tier != "easy":
            tabs.append("    [filter symbol/code      ]", style=DGRAY)
            tabs.append("  sort: ", style=LABEL)
            tabs.append("severity ▾", style=HILITE)
        yield Static(tabs, classes="rowbtn")
        with Horizontal(classes="body"):
            groups = Static(self._groups(), classes="fill pane")
            groups.border_title = "issues"
            groups.border_subtitle = f"E{e} W{warn}" if tier != "easy" else ""
            yield groups
            with Vertical(classes="pane issright"):
                if tier == "big":
                    d = Static(self._detail(), classes="detailcard")
                    d.border_title = "selected issue"
                    yield d
                hx = Static(hex_dump(w["mem"], w["ranges"][5][0] & ~0xF,
                                     6 if tier == "big" else 12, tier), classes="fill")
                hx.border_title = "Hex"
                yield hx
        e_, w_, i_ = e, warn, info
        summ = Text(" ")
        summ.append("total ", style=LABEL); summ.append(str(e_ + w_ + i_), style=VALUE)
        summ.append("  errors ", style=LABEL); summ.append(str(e_), style=f"bold {RED}")
        summ.append("  warnings ", style=LABEL); summ.append(str(w_), style=YELLOW)
        summ.append("  filter ", style=LABEL); summ.append("all", style=VALUE)
        summ.append("  page ", style=LABEL); summ.append("1/1", style=VALUE)
        yield Static(summ, classes="rowbtn")

    def _groups(self) -> Text:
        w, tier = self.world, self.tier
        t = Text()
        by_code: dict[str, list] = {}
        for issue in w["report"].issues:
            by_code.setdefault(issue.code, []).append(issue)
        shown = 0
        for code, items in sorted(by_code.items(),
                                  key=lambda kv: -sum("ERROR" in getattr(i.severity, "name", "")
                                                      for i in kv[1])):
            first = items[0]
            sev = getattr(first.severity, "name", "").upper()
            color = RED if "ERROR" in sev else YELLOW
            t.append("▍", style=color)                     # severity gutter
            t.append(f" {code} ", style=f"bold {color}")
            t.append(f"({len(items)})", style=LABEL)
            if tier != "easy":
                t.append("  ⌄", style=DGRAY)
            t.append("\n")
            for issue in items[:2]:
                t.append("▍", style=color)
                sym = getattr(issue, "symbol", None) or ""
                t.append(f"   {str(sym)[:20]:<21}", style=VALUE)
                addr = getattr(issue, "address", None)
                t.append(f"{f'0x{addr:08X}' if isinstance(addr, int) else '—':<12}", style=CYAN)
                t.append(str(issue.message)[:38], style=LABEL)
                if tier != "easy":
                    t.append("  ↵hex", style=HILITE)
                t.append("\n")
            shown += 1
            if shown >= 4:
                break
        return t

    def _detail(self) -> Text:
        issue = self.world["report"].issues[0]
        t = Text()
        t.append(f"{issue.code}\n", style=f"bold {RED}")
        t.append(str(issue.message)[:90] + "\n", style=VALUE)
        t.append("related ", style=LABEL)
        t.append(str(getattr(issue, "related_artifacts", None) or "—")[:40], style=DGRAY)
        t.append("\n")
        t.append("open in: ", style=LABEL)
        t.append("hex ↵", style=HILITE); t.append("  ")
        t.append("A2L ²", style=HILITE); t.append("  ")
        t.append("MAC ³", style=HILITE)
        return t


# ------------------------------------------------------------------ SCREEN 6: PATCH EDITOR
# Skeleton = batch-46's NEW three-window layout (PATCH SCRIPT / CHECKS / JSON EDIT,
# 3 columns >=120 cols, docked button rows). Tiers enhance THAT, not the retired 2x2.

DEMO_ENTRIES = [  # realistic change-set over the real prg.s19 image
    {"addr": 0x0000EB10, "bytes": [0x01, 0x02], "op": "patch-hex"},
    {"addr": 0x0000FCB4, "bytes": [0xAA, 0xBB, 0xCC], "op": "patch-hex"},
    {"addr": 0x000017E0, "bytes": [0xFF], "op": "set-byte"},
    {"addr": 0x20000000, "bytes": [0x00], "op": "patch-hex"},  # outside image
]


class PatchProto(Vertical):
    def __init__(self, world: dict, tier: str) -> None:
        super().__init__(classes="scrbody")
        self.world, self.tier = world, tier

    def _pe_entry_status(self, entry: dict) -> tuple[str, str, str]:
        mem, ranges = self.world["mem"], self.world["ranges"]
        inside = all((entry["addr"] + i) in mem for i in range(len(entry["bytes"])))
        if inside:
            return "✓", GREEN, "in-image"
        partially = any((entry["addr"] + i) in mem for i in range(len(entry["bytes"])))
        return ("◐", YELLOW, "partial") if partially else ("✗", RED, "outside image")

    def _pe_before_bytes(self, entry: dict) -> str:
        mem = self.world["mem"]
        return " ".join(
            f"{mem[entry['addr'] + i]:02X}" if (entry["addr"] + i) in mem else "--"
            for i in range(len(entry["bytes"]))
        )

    def _pe_entries_table(self) -> Text:
        tier = self.tier
        t = Text()
        hdr = Text()
        hdr.append(" # ", style=LABEL)
        hdr.append(" op         ", style=LABEL)
        hdr.append("address     ", style=LABEL)
        hdr.append("bytes        ", style=LABEL)
        if tier != "easy":
            hdr.append("chk", style=LABEL)
        t.append_text(hdr)
        t.append("\n")
        for i, entry in enumerate(DEMO_ENTRIES):
            glyph, color, _why = self._pe_entry_status(entry)
            t.append(f" {i + 1} ", style=VALUE)
            t.append(f" {entry['op']:<11}", style=PURPLE)
            t.append(f"0x{entry['addr']:08X}  ", style=CYAN)
            t.append(f"{' '.join(f'{b:02X}' for b in entry['bytes']):<13}", style=VALUE)
            if tier != "easy":
                t.append(glyph, style=f"bold {color}")
            t.append("\n")
        return t

    def _pe_buttons(self, labels: list[str], accent: str = LBLUE) -> Static:
        t = Text(" ")
        for lab in labels:
            t.append(f" {lab} ", style=f"bold {APP_BG} on {accent}")
            t.append(" ")
        return Static(t, classes="rowbtn")

    def _pe_checks_body(self) -> Text:
        tier = self.tier
        t = Text()
        ok = bad = 0
        for i, entry in enumerate(DEMO_ENTRIES):
            glyph, color, why = self._pe_entry_status(entry)
            ok += glyph == "✓"
            bad += glyph != "✓"
            t.append(f" {glyph} ", style=f"bold {color}")
            t.append(f"entry {i + 1}  ", style=VALUE)
            t.append(f"0x{entry['addr']:08X}  ", style=CYAN)
            t.append(why, style=color if glyph != "✓" else LABEL)
            t.append("\n")
        if tier == "easy":
            return t
        head = Text(" ")
        head.append("checks ", style=LABEL)
        head.append(f"{ok} pass ", style=GREEN)
        head.append(f"{bad} fail ", style=RED if bad else LABEL)
        head.append_text(microbar(ok / max(1, len(DEMO_ENTRIES)), 12,
                                  GREEN if not bad else YELLOW))
        head.append("\n\n")
        head.append_text(t)
        return head

    def _pe_json_body(self) -> Text:
        t = Text()
        lines = [
            ("{", DGRAY), ('  "schema": ', HILITE), ('"s19app-changes@2",', GREEN),
            ('  "entries": [', HILITE),
            ('    {"op": "patch-hex", "address": "0xEB10",', VALUE),
            ('     "bytes": "01 02"},', VALUE), ("    …", DGRAY), ("]}", DGRAY),
        ]
        for i, (line, color) in enumerate(lines):
            if self.tier == "easy":
                t.append(line + "\n", style=VALUE if i not in (0, 6, 7) else DGRAY)
            else:
                t.append(line + "\n", style=color)
        if self.tier != "easy":
            t.append("\n")
            t.append("paste cap ", style=LABEL)
            t.append("1.2KB / 64KB ", style=GREEN)
            t.append_text(microbar(0.02, 10, GREEN))
        return t

    def _pe_before_after(self) -> Text:
        entry = DEMO_ENTRIES[0]
        t = Text()
        t.append("entry 1 ", style=VALUE)
        t.append(f"0x{entry['addr']:08X}\n", style=CYAN)
        t.append("before ", style=LABEL)
        t.append(self._pe_before_bytes(entry) + "\n", style=DGRAY)
        t.append(" after ", style=LABEL)
        t.append(" ".join(f"{b:02X}" for b in entry["bytes"]), style=f"bold {GREEN}")
        t.append("  (live — today report-only)\n", style=DGRAY)
        t.append("history ", style=LABEL)
        t.append("◄ apply·2 ", style=HILITE)
        t.append("● now ", style=VALUE)
        t.append("undo ^z / redo ^y", style=DGRAY)
        return t

    def compose(self) -> ComposeResult:
        tier = self.tier
        head = Text(" ")
        head.append("Change file ", style=LABEL)
        head.append("patches/demo_fix.json ", style=VALUE)
        head.append("  variant ", style=LABEL)
        head.append("v2-fieldfix ▾ ", style=HILITE)
        head.append("?", style=f"bold {APP_BG} on {LBLUE}")
        head.append("   scope ", style=LABEL)
        head.append("project ▾", style=HILITE)
        yield Static(head, classes="rowbtn")
        with Horizontal(classes="body"):
            with Vertical(classes="pane"):
                yield Static(self._pe_entries_table(), classes="fill")
                if tier == "big":
                    card = Static(self._pe_before_after(), classes="pe-card")
                    card.border_title = "before / after (selected)"
                    yield card
                yield self._pe_buttons(["Add", "Edit", "Remove", "Edit JSON"])
                yield self._pe_buttons(["Load", "Refresh", "Validate", "Apply", "Save"], GREEN)
            with Vertical(classes="pane"):
                yield Static(self._pe_checks_body(), classes="fill")
                yield self._pe_buttons(["Run checks", "Undo ^z", "Redo ^y"], YELLOW)
            with Vertical(classes="pane"):
                yield Static(self._pe_json_body(), classes="fill")
                yield self._pe_buttons(["Parse pasted", "Edit JSON", "Write file"], LBLUE)

    def on_mount(self) -> None:
        panes = list(self.query(".pane"))
        titles = ["¹PATCH SCRIPT", "²CHECKS", "³JSON EDIT"]
        subs = [f"{len(DEMO_ENTRIES)} entries", "run: manual", "schema v2"]
        for pane, title, sub in zip(panes, titles, subs):
            pane.border_title = title
            if self.tier != "easy":
                pane.border_subtitle = sub


# ------------------------------------------------------------------ app
# One process = ONE (screen, tier) state, statically composed (the dynamic
# multi-state switcher deadlocked run_test boot; see NOTES). Interactive mode
# relaunches the app in-process on every switch; --check spawns one subprocess
# per state so each SVG export is isolated and deterministic.

SCREENS = [
    ("workspace", "Workspace", 0, WorkspaceProto),
    ("a2l", "A2L Explorer", 1, A2lProto),
    ("mac", "MAC View", 2, MacProto),
    ("map", "Memory Map", 3, MapProto),
    ("issues", "Issues Report", 4, IssuesProto),
    ("patch", "Patch Editor", 5, PatchProto),
]
TIERS = ["easy", "mid", "big"]


class ScreenUpgradesPrototype(App):
    CSS = f"""
    Screen {{ background: {APP_BG}; color: {VALUE}; }}
    .cmdbar {{ height: 3; border: round {BORDER}; padding: 0 1; margin: 0 1; }}
    .rail {{ width: 18; padding: 1 0 0 0; border-right: solid {BORDER}; }}
    .rail-row {{ height: 1; color: {LABEL}; }}
    .rail-active {{ background: #25406b; color: {VALUE}; text-style: bold; }}
    .body {{ height: 1fr; }}
    .state {{ height: 1fr; }}
    .scrbody {{ width: 1fr; }}
    .pane {{ border: tall {BORDER}; background: {PANEL_BG}; padding: 0 1; width: 1fr;
             border-title-color: {LBLUE}; border-title-style: bold;
             border-subtitle-color: {DGRAY}; }}
    .fill {{ height: 1fr; }}
    .rowbtn {{ height: 1; margin: 0 1; }}
    .memstrip {{ height: 1; margin: 0 1; }}
    .covstrip {{ height: 1; margin: 0 1; border-title-color: {DGRAY}; }}
    .statrow {{ height: 7; margin: 0 1; }}
    .statbox {{ border: tall {BORDER}; background: {PANEL_BG}; width: 1fr; margin-right: 1;
                border-title-color: {LBLUE}; border-title-style: bold; }}
    .detailcard {{ height: 8; border: tall #43548b; background: {ODD_BG}; padding: 0 1;
                   border-title-color: {LBLUE}; }}
    .stats {{ height: 7; }}
    .glance {{ height: 8; }}
    .pe-card {{ height: 6; border: tall #43548b; background: #131a2c; padding: 0 1;
                border-title-color: #bbc8e8; }}
    .wsleft {{ max-width: 36; }}
    .wsright {{ max-width: 34; }}
    .a2lright {{ max-width: 64; }}
    .macleft {{ max-width: 46; }}
    .mapright {{ max-width: 40; }}
    .issright {{ max-width: 62; }}
    DataTable {{ background: {PANEL_BG}; height: 1fr; }}
    DataTable > .datatable--header {{ background: {PANEL_BG}; color: {LABEL}; }}
    DataTable > .datatable--odd-row {{ background: {ODD_BG}; }}
    .footbar {{ height: 1; }}
    #proto_bar {{ dock: bottom; height: 1; background: #5b2430; color: {VALUE}; text-style: bold; }}
    #titlerow {{ height: 1; text-align: center; color: {LABEL}; }}
    """

    BINDINGS = (
        [("q", "quit", "quit")]
        + [(str(i + 1), f"switch({i}, -1)", n) for i, (_, n, _, _) in enumerate(SCREENS)]
        + [("left_square_bracket", "switch(-1, 0)", "tier-"),
           ("right_square_bracket", "switch(-1, 1)", "tier+")]
    )

    def __init__(self, world: dict, scr_i: int = 0, tier_i: int = 0) -> None:
        super().__init__()
        self.world = world
        self.scr_i, self.tier_i = scr_i, tier_i
        self.next_state: tuple[int, int] | None = None

    def compose(self) -> ComposeResult:
        key, name, rail_idx, cls = SCREENS[self.scr_i]
        tier = TIERS[self.tier_i]
        yield Static("Hex Edit Tool", id="titlerow")
        yield command_bar(self.world)
        with Horizontal(classes="state"):
            yield build_rail(rail_idx)
            yield cls(self.world, tier)
        yield Static(Text(" Ready.", style=DGRAY), classes="rowbtn")
        yield footer_bar()
        yield Static(
            f" PROTOTYPE ▸ {name} · tier {tier.upper()} ({self.scr_i + 1}/{len(SCREENS)})"
            f"  — 1-5 screen · [ ] tier · q quit — skeleton = current app",
            id="proto_bar",
        )

    def action_switch(self, scr: int, tier_step: int) -> None:
        nscr = self.scr_i if scr < 0 else scr
        ntier = self.tier_i
        if tier_step == 0:
            ntier = (self.tier_i - 1) % len(TIERS)
        elif tier_step == 1:
            ntier = (self.tier_i + 1) % len(TIERS)
        self.next_state = (nscr, ntier)
        self.exit()


def shoot(scr_key: str, tier: str, width: int, height: int) -> None:
    """Export one state's SVG (run in an isolated subprocess by --check)."""
    import asyncio

    scr_i = next(i for i, s in enumerate(SCREENS) if s[0] == scr_key)
    tier_i = TIERS.index(tier)

    async def run() -> None:
        app = ScreenUpgradesPrototype(load_world(), scr_i, tier_i)
        async with app.run_test(size=(width, height)) as pilot:
            await pilot.pause()
            out = REPO / "prototypes" / "out"
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"set_{scr_key}_{tier}_{width}x{height}.svg"
            path.write_text(app.export_screenshot(), encoding="utf-8")
            print("wrote", path.name, flush=True)

    asyncio.run(run())


def check_all() -> None:
    import subprocess

    jobs = [(k, t, 120, 30) for k, _, _, _ in SCREENS for t in TIERS]
    jobs += [(k, "big", 160, 42) for k, _, _, _ in SCREENS]
    failed = []
    for key, tier, wdt, hgt in jobs:
        res = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--shoot", key, tier, str(wdt), str(hgt)],
            capture_output=True, text=True, timeout=90,
        )
        line = (res.stdout or "").strip().splitlines()[-1:] or ["(no output)"]
        print(f"[{key}/{tier}@{wdt}x{hgt}] rc={res.returncode} {line[0]}", flush=True)
        if res.returncode != 0:
            failed.append((key, tier, wdt, hgt, (res.stderr or "")[-400:]))
    if failed:
        print(f"\n{len(failed)} FAILED:")
        for f in failed:
            print(f)
        sys.exit(1)
    print(f"\nall {len(jobs)} exports OK -> prototypes/out/")


if __name__ == "__main__":
    if "--shoot" in sys.argv:
        i = sys.argv.index("--shoot")
        shoot(sys.argv[i + 1], sys.argv[i + 2], int(sys.argv[i + 3]), int(sys.argv[i + 4]))
    elif "--check" in sys.argv:
        check_all()
    else:
        world = load_world()
        scr_i, tier_i = 0, 0
        while True:
            app = ScreenUpgradesPrototype(world, scr_i, tier_i)
            app.run()
            if app.next_state is None:
                break
            scr_i, tier_i = app.next_state
