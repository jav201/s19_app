"""Scratch probe: regions of the Inspector entry boxes after the Inspector chip press (not committed)."""
import pytest
from tests.support import b103_inc10 as t


@pytest.mark.parametrize("size", [(160, 54), (118, 54), (220, 60)])
def test_probe(tmp_path, size):
    async def body(app, pilot):
        await t.click_tab(pilot, "patch_tab_inspector")
        out = []
        for wid in ("patch_entry_address_input", "patch_entry_bytes_input", "patch_entry_add_button"):
            w = app.screen.query_one("#" + wid)
            hit, _ = app.get_widget_at(*w.region.center) if w.region.area else (None, None)
            out.append((wid, str(w.region), t.shown(w), getattr(hit, "id", None)))
        out.append(("screen", str(app.screen.region)))
        return out

    for row in t.run_loaded(tmp_path, size, "firmware.s19", body):
        print("PROBE", size, row)
