"""Inc 10 E1 confirmation pilot (batch-101). Headless; run from the worktree root.

D4A  : A2L explorer value column after an in-place change apply (Inc 5 ruling D-4 (a)).
D4B  : Split / Join window after an in-place change apply (Inc 5 ruling D-4 (b)).
F07  : where the target row lands after go-to / Find Next / section jump (main, A2L, MAC).
M06  : the `> ` marker after a failed go-to and after a section jump (D4-6).
F13  : the status text after `[u]` / `U`; unload-all with nothing loaded (D5-17, D5-27).
D519 : primary unload with a MAC loaded: diagnostics and path (D5-19).
F14  : the focus after unload, after closing Split / Join, after a rail key (D17-38, D6-21).
F18  : the `t` that opens the manual tab (F-18).
SE5  : a bidi control in a loaded file name and the status text (SE5-12a-2).
Prints one JSON transcript per scenario; nothing outside the run folder is written.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sys
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools" / "synth"))

import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

import make_release_case as gen  # noqa: E402
from textual.containers import ScrollableContainer  # noqa: E402
from textual.widgets import DataTable, Label, Static, TextArea  # noqa: E402

from s19_app.tui.app import S19TuiApp  # noqa: E402
from s19_app.tui.screens_directionb import PatchEditorPanel  # noqa: E402
from s19_app.tui.segment_split_view import SplitJoinWindow  # noqa: E402
from tests.support.b100_projects import StatusLog  # noqa: E402
from tests.support.timing import wait_until  # noqa: E402

RUN = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/i10e1/run")
SIZE = (120, 56)  # measured screen 118 x 54, the guide's regime


def s1(addr: int, data: bytes) -> str:
    body = bytes([len(data) + 3, addr >> 8, addr & 0xFF]) + data
    return "S1" + body.hex().upper() + f"{(~sum(body)) & 0xFF:02X}"


def write_three_ranges(path: Path) -> None:
    lines = [
        "S0030000FC",
        s1(0x8000, bytes(range(8))),
        s1(0x8010, b"\xff" * 8),
        s1(0x8020, bytes(range(0x20, 0x28))),
        "S9030000FC",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="ascii")


async def settle(pilot, n: int = 6) -> None:
    for _ in range(n):
        await pilot.pause()


def plain(widget) -> str:
    content = getattr(widget, "content", None)
    if content is None:
        content = widget.renderable
    return str(content)


def last(log):
    return log.messages[-1] if log.messages else None


def status_text(app) -> str:
    return plain(app.query_one("#status_text", Label))


def focused(app) -> dict:
    w = app.default_screen.focused
    if w is None:
        return {"id": None}
    hidden_window = None
    for anc in w.ancestors:
        if anc.id in getattr(app, "_WINDOW_CONTAINER_IDS", ()):
            hidden_window = anc.has_class("hidden")
            break
    return {
        "id": w.id,
        "type": type(w).__name__,
        "area": w.region.area,
        "window_hidden": hidden_window,
    }


def change_doc(folder: Path, name: str, addr: int, value: int, extra=()) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    entries = [{"type": "bytes", "address": f"0x{a:X}", "bytes": f"{v:02X}"}
               for a, v in [(addr, value), *extra]]
    doc = folder / name
    doc.write_text(
        json.dumps(
            {
                "format": "s19app-changeset",
                "version": "2.0",
                "kind": "change",
                "encoding": "utf-8",
                "value_mode": "text",
                "entries": entries,
            }
        ),
        encoding="utf-8",
    )
    return doc


async def apply_doc(pilot, app, log, doc: Path) -> list:
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    mark = len(log.messages)
    panel.post_message(PatchEditorPanel.ActionRequested("load_doc", path_text=str(doc)))
    await settle(pilot)
    panel.post_message(PatchEditorPanel.ActionRequested("apply_doc"))
    await wait_until(
        pilot,
        lambda: any(m.startswith("Apply:") for m in log.since(mark)),
        lambda: f"apply status: {log.since(mark)!r}",
    )
    await settle(pilot)
    return list(log.since(mark))


async def load_image(pilot, app, path: Path) -> None:
    app.load_selected_file(path)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.path.name == path.name,
        f"load of {path.name}",
    )
    await settle(pilot, 10)


async def load_a2l(pilot, app, path: Path) -> None:
    app.load_a2l_from_path(path)
    await wait_until(pilot, lambda: app.current_a2l_data is not None, "A2L load")
    await settle(pilot, 10)


async def load_mac(pilot, app, path: Path) -> None:
    app.load_selected_file(path)
    await wait_until(
        pilot,
        lambda: app.current_file is not None and app.current_file.mac_path is not None,
        "MAC load",
    )
    await settle(pilot, 10)


def tag_row(app, name: str) -> dict:
    table = app.query_one("#a2l_tags_list", DataTable)
    labels = [str(c.label) for c in table.columns.values()]
    for i in range(table.row_count):
        row = [str(v) for v in table.get_row_at(i)]
        if any(name in cell for cell in row):
            return dict(zip(labels, row))
    first = [str(v) for v in table.get_row_at(0)] if table.row_count else []
    return {"_missing": name, "rows": table.row_count, "first_row": dict(zip(labels, first))}


def hex_geometry(app, view_id: str, scroll_id: str) -> dict:
    lines = plain(app.query_one(view_id, Static)).splitlines()
    marker = next((i for i, ln in enumerate(lines) if ln.startswith("> ")), None)
    rows = [i for i, ln in enumerate(lines) if ln.startswith(("> ", "  0x"))]
    scroll = app.query_one(scroll_id, ScrollableContainer)
    height = scroll.scrollable_content_region.height
    out = {
        "notice_lines": [ln for ln in lines if ln.startswith("...")],
        "first_row": lines[rows[0]][:14] if rows else None,
        "rows": len(rows),
        "marker_line": marker,
        "marker_row_index": (rows.index(marker) if marker in rows else None),
        "scroll_y": scroll.scroll_y,
        "scroll_x": scroll.scroll_x,
        "viewport_rows": height,
    }
    if marker is not None:
        out["marker_visible"] = scroll.scroll_y <= marker < scroll.scroll_y + height
    return out


def row_line_index(app, view_id: str, address: int) -> int | None:
    lines = plain(app.query_one(view_id, Static)).splitlines()
    tag = f"0x{address - address % 16:08X}"
    return next((i for i, ln in enumerate(lines) if ln[2:12] == tag), None)


async def type_into(pilot, key: str, text: str) -> None:
    await pilot.press(key)
    await settle(pilot, 2)
    await pilot.press(*list(text))
    # Enter in the box runs nothing (no Input.Submitted route): Tab to the
    # button, then Enter, as the user guide does.
    await pilot.press("tab", "enter")
    await settle(pilot)


def run_case(base: Path, scenario, size=SIZE):
    base.mkdir(parents=True, exist_ok=True)
    app = S19TuiApp(base_dir=base)
    log = StatusLog(app)

    async def drive():
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            return await scenario(app, pilot, log)

    return asyncio.run(drive())


# --------------------------------------------------------------------------- D4A
async def d4a(app, pilot, log, case: Path) -> dict:
    out: dict = {"scenario": "D4A"}
    await load_image(pilot, app, case / "firmware.s19")
    await load_a2l(pilot, app, case / "firmware.a2l")
    await pilot.press("2")
    await settle(pilot, 10)
    tags = app._a2l_enriched_tags
    tag = next(t for t in tags if t.get("in_memory") and isinstance(t.get("address"), int))
    name, addr = str(tag["name"]), int(tag["address"])
    mem = app.current_file.mem_map
    old = mem[addr]
    out["tag"] = {"name": name, "address": f"0x{addr:08X}", "length": tag.get("length"),
                  "datatype": tag.get("datatype")}
    out["row_before"] = tag_row(app, name)
    out["byte_before"] = f"0x{old:02X}"
    key_before = app._a2l_enriched_key
    await pilot.press("6")
    await settle(pilot)
    out["apply_status"] = await apply_doc(
        pilot, app, log, change_doc(app._patches_dir(), "d4a.changes.json", addr, old ^ 0xFF)
    )
    out["byte_after"] = f"0x{mem[addr]:02X}"
    out["same_mem_map_object"] = app.current_file.mem_map is mem
    await pilot.press("2")
    await settle(pilot, 10)
    out["row_after_reshow"] = tag_row(app, name)
    out["enriched_key_unchanged"] = app._a2l_enriched_key == key_before
    fresh = next(t for t in app._a2l_enriched_tags if t.get("name") == name)
    out["cached_tag_raw_value_after"] = fresh.get("raw_value")
    # Oracle: the same enrichment with the cache key dropped.
    app._a2l_enriched_key = None
    oracle = next(t for t in app._compute_a2l_enriched_tags() if t.get("name") == name)
    out["oracle_raw_value_after"] = oracle.get("raw_value")
    out["oracle_physical_value_after"] = oracle.get("physical_value")
    out["painted_matches_post_apply_bytes"] = str(oracle.get("raw_value")) in out[
        "row_after_reshow"
    ].values()
    return out


# --------------------------------------------------------------------------- D4B
async def d4b(app, pilot, log, base: Path) -> dict:
    out: dict = {"scenario": "D4B"}
    img = base / "three.s19"
    write_three_ranges(img)
    await load_image(pilot, app, img)
    app.action_open_split_join_export()
    await settle(pilot, 10)
    win = app.query_one("#screen_split_join", SplitJoinWindow)
    out["tab"] = win._tab
    out["default_pad"] = f"0x{win._pad_int:02X}"
    if win._pad_int != 0xFF:
        await pilot.press("p")  # pad 0xFF: the middle range is all pad, no conflict
    # ranges tab: t cycles a2l -> ranges -> manual; the window opens on ranges
    await pilot.press("m")  # join (gap concat)
    await pilot.press("g")  # fill
    await pilot.press("space")  # range_00
    await pilot.press("j", "j", "space")  # range_02
    await settle(pilot)
    stats = lambda: plain(win.query_one("#sje_stats", Static))  # noqa: E731
    out["mode_gap_sel"] = [win._mode, win._gap, sorted(win._sel[win._tab])]
    out["stats_before"] = stats()
    out["oracle_conflicts_before"] = win._plan(win._rows()).conflicts
    # (b1) the write while the window is hidden, then the palette reopens it
    await pilot.press("escape")
    await settle(pilot)
    await pilot.press("6")
    await settle(pilot)
    out["b1_apply"] = await apply_doc(
        pilot, app, log, change_doc(app._patches_dir(), "d4b1.changes.json", 0x8013, 0xAA)
    )
    app.action_open_split_join_export()
    await settle(pilot, 10)
    out["b1_sel_after_reopen"] = sorted(win._sel[win._tab])
    out["b1_stats_after_reopen"] = stats()
    out["b1_oracle_conflicts"] = win._plan(win._rows()).conflicts
    # (b2) the write while the window is displayed (message posted, no key)
    out["b2_apply"] = await apply_doc(
        pilot, app, log, change_doc(app._patches_dir(), "d4b2.changes.json", 0x8015, 0xBB,
                                    extra=[(0x8016, 0xCC)])
    )
    await settle(pilot, 10)
    mem = app.current_file.mem_map
    out["b2_bytes_8010_8017"] = " ".join(f"{mem.get(a, 0):02X}" for a in range(0x8010, 0x8018))
    band = win.query_one("#sje_band")
    out["b2_painted_band"] = [(b.cls, b.size) for b in band._blocks]
    out["b2_oracle_band"] = [(b.cls, b.size) for b in win._plan(win._rows()).map_blocks]
    out["b2_stats_while_shown"] = stats()
    out["b2_oracle_conflicts"] = win._plan(win._rows()).conflicts
    return out


# --------------------------------------------------------------------------- D4C
async def d4c(app, pilot, log, base: Path) -> dict:
    """D-4 (b) on a user path: the Save project commit re-derives the image in
    place while the Split / Join window is displayed."""
    from tests.support.b100_projects import save_project

    out: dict = {"scenario": "D4C"}
    img = base / "three.s19"
    write_three_ranges(img)
    await load_image(pilot, app, img)
    await pilot.press("6")
    await settle(pilot)
    out["apply_1"] = await apply_doc(
        pilot, app, log, change_doc(app._patches_dir(), "d4c1.changes.json", 0x8013, 0xAA)
    )
    panel = app.query_one("#patch_editor_panel", PatchEditorPanel)
    doc2 = change_doc(app._patches_dir(), "d4c2.changes.json", 0x8015, 0xBB, extra=[(0x8016, 0xCC)])
    panel.post_message(PatchEditorPanel.ActionRequested("load_doc", path_text=str(doc2)))
    await settle(pilot)
    mem = app.current_file.mem_map
    out["bytes_before_save"] = " ".join(f"{mem.get(a, 0):02X}" for a in range(0x8010, 0x8018))
    app.action_open_split_join_export()
    await settle(pilot, 10)
    win = app.query_one("#screen_split_join", SplitJoinWindow)
    if win._pad_int != 0xFF:
        await pilot.press("p")
    await pilot.press("m", "g", "space", "j", "j", "space")
    await settle(pilot)
    band = win.query_one("#sje_band")
    out["painted_band_before_save"] = [(b.cls, b.size) for b in band._blocks]
    out["save_status"] = await save_project(pilot, app, log, "P10")
    await settle(pilot, 10)
    out["split_join_displayed_after_save"] = not win.has_class("hidden")
    out["same_mem_map_object"] = app.current_file.mem_map is mem
    out["bytes_after_save"] = " ".join(f"{mem.get(a, 0):02X}" for a in range(0x8010, 0x8018))
    out["painted_band_after_save"] = [(b.cls, b.size) for b in band._blocks]
    out["oracle_band_after_save"] = [(b.cls, b.size) for b in win._plan(win._rows()).map_blocks]
    out["painted_state_after_save"] = plain(win.query_one("#sje_stats", Static))
    return out


# --------------------------------------------------------------------------- F07
async def f07(app, pilot, log, case: Path) -> dict:
    out: dict = {"scenario": "F07"}
    await load_image(pilot, app, case / "firmware.s19")
    await load_a2l(pilot, app, case / "firmware.a2l")
    await load_mac(pilot, app, case / "firmware.mac")
    bases = app.current_file.row_bases
    page = app._clamp_viewer_page_size(app.hex_rows_page_size)
    out["row_count"], out["page_size"] = len(bases), page
    target = bases[150]
    out["target"] = f"0x{target:08X} (row index 150)"
    await pilot.press("1")
    await settle(pilot)
    await type_into(pilot, "g", f"0x{target:08X}")
    out["main_goto"] = hex_geometry(app, "#hex_view", "#hex_scroll")
    # user scrolls down and right, then a second go-to
    sc = app.query_one("#hex_scroll", ScrollableContainer)
    sc.scroll_to(x=10, y=40, animate=False)
    await settle(pilot)
    target2 = bases[20]
    await type_into(pilot, "g", f"0x{target2:08X}")
    out["main_goto_after_scroll"] = hex_geometry(app, "#hex_view", "#hex_scroll")
    # Find Next on a known text
    from s19_app.render.hexview import find_string_in_mem
    hit = find_string_in_mem(app.current_file.mem_map, "BUILD_ID", None)
    out["search_hit"] = f"0x{hit:08X}" if hit is not None else None
    if hit is not None:
        sc.scroll_to(x=0, y=0, animate=False)
        await settle(pilot)
        await type_into(pilot, "slash", "BUILD_ID")
        out["main_find_next"] = {
            "status": last(log),
            "hit_line": row_line_index(app, "#hex_view", hit),
            **{k: v for k, v in hex_geometry(app, "#hex_view", "#hex_scroll").items()
               if k in ("first_row", "notice_lines", "scroll_y", "viewport_rows")},
        }
    # section jump: the second data section
    lv = app.query_one("#sections_list")
    out["sections"] = len(lv.children)
    if len(lv.children) > 1:
        item = lv.children[1]
        start = item.data[0] if getattr(item, "data", None) else None
        app._jump_to_section(item)
        await settle(pilot)
        out["section_jump"] = {
            "start": f"0x{start:08X}" if start is not None else None,
            "start_line": row_line_index(app, "#hex_view", start) if start is not None else None,
            **{k: v for k, v in hex_geometry(app, "#hex_view", "#hex_scroll").items()
               if k in ("first_row", "scroll_y", "viewport_rows", "marker_line")},
        }
    # MAC view go-to
    await pilot.press("3")
    await settle(pilot, 8)
    await type_into(pilot, "g", f"0x{target:08X}")
    out["mac_goto"] = hex_geometry(app, "#mac_hex_view", "#mac_hex_scroll")
    # A2L view go-to
    await pilot.press("2")
    await settle(pilot, 8)
    await type_into(pilot, "g", f"0x{target:08X}")
    out["a2l_goto"] = hex_geometry(app, "#alt_hex_view", "#alt_hex_scroll")
    out["status_tail"] = log.messages[-4:]
    return out


# --------------------------------------------------------------------------- M06
async def m06(app, pilot, log, case: Path) -> dict:
    out: dict = {"scenario": "M06"}
    await load_image(pilot, app, case / "firmware.s19")
    bases = app.current_file.row_bases
    await pilot.press("1")
    await settle(pilot)
    await type_into(pilot, "g", f"0x{bases[5]:08X}")
    out["after_goto_hit_marker_line"] = hex_geometry(app, "#hex_view", "#hex_scroll")["marker_line"]
    await type_into(pilot, "g", "0xFFFFFFF0")
    out["after_goto_miss_status"] = last(log)
    out["after_goto_miss_marker_line"] = hex_geometry(app, "#hex_view", "#hex_scroll")["marker_line"]
    await type_into(pilot, "g", "zz")
    out["after_goto_invalid_status"] = last(log)
    out["after_goto_invalid_marker_line"] = hex_geometry(app, "#hex_view", "#hex_scroll")["marker_line"]
    await type_into(pilot, "g", f"0x{bases[5]:08X}")
    lv = app.query_one("#sections_list")
    app._jump_to_section(lv.children[-1])
    await settle(pilot)
    out["after_section_jump_marker_line"] = hex_geometry(app, "#hex_view", "#hex_scroll")["marker_line"]
    out["after_section_jump_marker_field"] = app._goto_focus_address
    return out


# --------------------------------------------------------------------------- F13
async def f13(app, pilot, log, case: Path) -> dict:
    out: dict = {"scenario": "F13"}
    await pilot.press("U")
    await settle(pilot)
    out["U_nothing_loaded_message"] = log.messages[-1] if log.messages else None
    await load_image(pilot, app, case / "firmware.s19")
    await load_mac(pilot, app, case / "firmware.mac")
    out["status_after_loads"] = status_text(app)
    app._apply_unload("mac")
    await settle(pilot)
    out["after_u_mac"] = {"status_text": status_text(app), "message": log.messages[-1]}
    await pilot.press("U")
    await settle(pilot)
    out["after_U"] = {"status_text": status_text(app), "message": log.messages[-1]}
    return out


# --------------------------------------------------------------------------- D519
async def d519(app, pilot, log, base: Path, case: Path) -> dict:
    out: dict = {"scenario": "D519"}
    img = base / "bad.s19"
    good = s1(0x8000, bytes(range(8)))
    bad = good[:-2] + ("00" if good[-2:] != "00" else "01")  # wrong checksum
    img.write_text("\n".join(["S0030000FC", good, bad.replace("S1", "S1", 1), "S9030000FC"]) + "\n")
    await load_image(pilot, app, img)
    await load_mac(pilot, app, case / "firmware.mac")
    out["errors_before"] = len(app.current_file.errors)
    out["path_before"] = app.current_file.path.name
    app._apply_unload("primary")
    await settle(pilot)
    cf = app.current_file
    out["after_primary_unload"] = {
        "file_type": cf.file_type if cf else None,
        "errors": len(cf.errors) if cf else None,
        "path": cf.path.name if cf else None,
        "status_text": status_text(app),
    }
    return out


# --------------------------------------------------------------------------- F14
async def f14(app, pilot, log, case: Path) -> dict:
    out: dict = {"scenario": "F14"}
    await load_image(pilot, app, case / "firmware.s19")
    out["after_load"] = focused(app)
    await pilot.press("2")
    await settle(pilot)
    out["after_key_2"] = focused(app)
    await pilot.press("1")
    await settle(pilot)
    out["after_key_1"] = focused(app)
    app.query_one("#files_list").focus()
    await settle(pilot)
    out["before_U"] = focused(app)
    await pilot.press("U")
    await settle(pilot)
    out["after_U"] = focused(app)
    await load_image(pilot, app, case / "firmware.s19")
    app.action_open_split_join_export()
    await settle(pilot, 8)
    out["after_open_split_join"] = focused(app)
    await pilot.press("escape")
    await settle(pilot)
    out["after_esc_close"] = {**focused(app), "active": app._active_screen_key}
    app.action_open_split_join_export()
    await settle(pilot, 8)
    await pilot.press("3")
    await settle(pilot)
    out["after_rail_key_close"] = {**focused(app), "active": app._active_screen_key}
    await pilot.press("down")
    await settle(pilot)
    return out


# --------------------------------------------------------------------------- F18
async def f18(app, pilot, log, base: Path) -> dict:
    out: dict = {"scenario": "F18"}
    img = base / "three.s19"
    write_three_ranges(img)
    await load_image(pilot, app, img)
    app.action_open_split_join_export()
    await settle(pilot, 8)
    win = app.query_one("#screen_split_join", SplitJoinWindow)
    seen = [win._tab]
    for _ in range(3):
        if win._tab == "manual":
            break
        await pilot.press("t")
        await settle(pilot)
        seen.append(win._tab)
    out["tabs_seen"] = seen
    out["manual_text_after_t"] = win.query_one("#sje_manual", TextArea).text
    out["focus"] = focused(app)
    await pilot.press("t")  # a second t, now inside the focused manual box
    await settle(pilot)
    out["after_second_t"] = {"tab": win._tab,
                             "manual_text": win.query_one("#sje_manual", TextArea).text}
    return out


# --------------------------------------------------------------------------- SE5
async def se5(app, pilot, log, base: Path) -> dict:
    out: dict = {"scenario": "SE5"}
    img = base / "fw‮gpj.s19"
    write_three_ranges(img)
    await load_image(pilot, app, img)
    st = status_text(app)
    out["status_text_codepoints_cf"] = [f"U+{ord(c):04X}" for c in st if ord(c) in (0x202E, 0x200B, 0x2066)]
    out["status_text_ascii"] = st.encode("ascii", "backslashreplace").decode()
    out["last_message_ascii"] = str(last(log)).encode("ascii", "backslashreplace").decode()
    return out


def main() -> None:
    os.environ.setdefault("LOCALAPPDATA", str(RUN / "localappdata"))
    if RUN.exists():
        shutil.rmtree(RUN)
    RUN.mkdir(parents=True)
    case = RUN / "case08"
    gen.generate(case, 20260001, 1.0)
    which = sys.argv[2:] or ["D4A", "D4B", "D4C", "F07", "M06", "F13", "D519", "F14", "F18", "SE5"]
    table = {
        "D4A": lambda b: run_case(b, lambda a, p, l: d4a(a, p, l, case)),
        "D4B": lambda b: run_case(b, lambda a, p, l: d4b(a, p, l, b)),
        "D4C": lambda b: run_case(b, lambda a, p, l: d4c(a, p, l, b)),
        "F07": lambda b: run_case(b, lambda a, p, l: f07(a, p, l, case)),
        "M06": lambda b: run_case(b, lambda a, p, l: m06(a, p, l, case)),
        "F13": lambda b: run_case(b, lambda a, p, l: f13(a, p, l, case)),
        "D519": lambda b: run_case(b, lambda a, p, l: d519(a, p, l, b, case)),
        "F14": lambda b: run_case(b, lambda a, p, l: f14(a, p, l, case)),
        "F18": lambda b: run_case(b, lambda a, p, l: f18(a, p, l, b)),
        "SE5": lambda b: run_case(b, lambda a, p, l: se5(a, p, l, b)),
    }
    for name in which:
        try:
            result = table[name](RUN / name.lower())
        except Exception as exc:  # report and continue
            result = {"scenario": name, "error": f"{type(exc).__name__}: {exc}"}
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
