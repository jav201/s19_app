"""Inc 10 E1 census B — where the save-back prompt is after an apply, per inspector tab (base e07fb00).

Headless Pilot at 118x54 and 220x60 (the probe sizes). Loads case01 firmware.s19 through the Load dialog, adds
one inside entry through the panel, presses Apply, then shows each inspector tab in turn and measures the prompt
row, its Write file button, the widget actually under that button's centre (a non-mutating hit test), and the
vertical budget of the screen. Then: a second apply that applies nothing (the entry replaced by one outside the
image) — is the prompt hidden? No Write file press, no clipboard. Run on cachyos-rtx with HOME/XDG/LOCALAPPDATA
under /tmp/b103-e1-10/.
"""
import asyncio
import os
import shutil
import sys
from pathlib import Path

ROOT = Path("/home/javiergr/work/s19_app")  # absolute: HOME is isolated
sys.path.insert(0, str(ROOT))
import s19_app  # noqa: E402

print("s19_app.__file__ =", s19_app.__file__)

from tests.test_b100_save_image import (  # noqa: E402
    CASE01_DIR,
    _add_entry_through_the_panel,
    _load_file_through_dialog,
    _status_text,
    _wait_for,
)
from s19_app.tui.app import S19TuiApp  # noqa: E402

W = Path(os.environ["CENSUS"])
TABS = ("patch_tab_inspector", "patch_tab_json", "patch_tab_checks", "patch_tab_a2l")


def geom(app, sel):
    found = list(app.query(sel))
    if not found:
        return "ABSENT"
    w = found[0]
    hidden_by = []
    n = w
    while n is not None:
        if not n.display:
            hidden_by.append(n.id or type(n).__name__)
        n = n.parent
    return "region=%s shown=%s hidden_by=%s" % (tuple(w.region), not hidden_by, hidden_by)


def hit(app, sel):
    found = list(app.query(sel))
    if not found:
        return "ABSENT"
    r = found[0].region
    if r.width == 0 or r.height == 0:
        return "no region"
    x, y = r.x + r.width // 2, r.y + r.height // 2
    try:
        widget, _ = app.screen.get_widget_at(x, y)
    except Exception as exc:  # noqa: BLE001
        return "%s at (%d,%d)" % (type(exc).__name__, x, y)
    return "(%d,%d) -> #%s" % (x, y, widget.id)


async def scene(size):
    tag = "%dx%d" % size
    base = W / ("app-" + tag)
    src_dir = W / ("src-" + tag)
    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(src_dir, ignore_errors=True)
    src_dir.mkdir(parents=True)
    src = src_dir / "firmware.s19"
    shutil.copy2(CASE01_DIR / "firmware.s19", src)
    app = S19TuiApp(base_dir=base)
    async with app.run_test(size=size, notifications=True) as pilot:
        await pilot.pause()
        await _load_file_through_dialog(pilot, app, src)
        await _add_entry_through_the_panel(pilot, app, "0x8000007C", "DE AD BE EF")
        assert await pilot.click("#patch_doc_apply_button")
        await _wait_for(pilot, lambda: _status_text(app).startswith("Apply:"), "the apply status")
        for _ in range(5):
            await pilot.pause()
        print("  screen", tuple(app.screen.size), "status", repr(_status_text(app)))
        print("  notices after apply", [str(n.message) for n in app._notifications])
        print("  row hidden class", app.query_one("#patch_saveback_row").has_class("hidden"))
        panel = app.query_one("#patch_editor_panel")
        print("  panel", tuple(panel.region), "max_scroll_y", panel.max_scroll_y)
        for sel in ("#patch_main", "#patch_inspector", "#patch_tab_switcher", "#patch_doc_file_row",
                    "#patch_doc_controls", "#patch_legend", "#status_text"):
            print("  ", sel, geom(app, sel))
        for chip in TABS:
            assert await pilot.click("#" + chip), chip
            for _ in range(4):
                await pilot.pause()
            print("  TAB", chip, "switcher.current", app.query_one("#patch_tab_switcher").current)
            print("     row    ", geom(app, "#patch_saveback_row"))
            print("     write  ", geom(app, "#patch_saveback_confirm_button"), "hit", hit(app, "#patch_saveback_confirm_button"))
            print("     width  ", geom(app, "#patch_saveback_width_button"))
            print("     apply  ", geom(app, "#patch_doc_apply_button"), "hit", hit(app, "#patch_doc_apply_button"))
        # back to the Inspector; replace the entry by one outside the image and apply again
        assert await pilot.click("#patch_tab_inspector")
        await pilot.pause()
        # census shortcut (not a test): the boxes still hold the first entry's text, and ctrl+a in an
        # Input moves to the line start, so clear the two boxes directly before the next typed input.
        app.query_one("#patch_entry_address_input").value = "0x8000007C"
        assert await pilot.click("#patch_entry_remove_button")
        for _ in range(10):
            await pilot.pause()
        print("  after Remove: status", repr(_status_text(app)), "entries",
              len(app._change_service.document.entries),
              "address box", repr(app.query_one("#patch_entry_address_input").value))
        app.query_one("#patch_entry_address_input").value = ""
        app.query_one("#patch_entry_bytes_input").value = ""
        await _add_entry_through_the_panel(pilot, app, "0x00000010", "AA")
        assert await pilot.click("#patch_doc_apply_button")
        await _wait_for(pilot, lambda: _status_text(app).startswith("Apply: 0"), "the zero apply status")
        for _ in range(5):
            await pilot.pause()
        print("  ZERO-APPLY status", repr(_status_text(app)))
        print("  ZERO-APPLY row hidden class", app.query_one("#patch_saveback_row").has_class("hidden"))
        print("  ZERO-APPLY notices", [str(n.message) for n in app._notifications])
        print("  ZERO-APPLY image byte 0x8000007C", hex(app.current_file.mem_map[0x8000007C]))


async def main():
    for size in ((118, 54), (220, 60)):
        print("=== SIZE", size)
        try:
            await scene(size)
        except Exception:  # noqa: BLE001
            import traceback

            traceback.print_exc()
    print("END")


asyncio.run(main())
