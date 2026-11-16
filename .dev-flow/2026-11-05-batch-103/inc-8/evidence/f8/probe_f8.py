"""Scratch probe F8: Inspector pane widget regions vs the pane's viewport (not committed)."""
import pytest
from textual.widget import Widget
from tests.support import b103_inc8_p as p
from tests.b97_probes import painted_rows


@pytest.mark.parametrize("size", [(118, 54), (220, 60), (80, 24)])
def test_probe(tmp_path, size):
    defc = p.build_defc(tmp_path / "defc")

    async def body(app, pilot, panel):
        await p.show_tab(pilot, "patch_tab_inspector")
        pane = app.screen.query_one("#patch_pane_inspector")
        print("PROBE", size, "screen", app.screen.region, "panel", panel.region, "panel.scroll_y", panel.scroll_y,
              "pane", pane.region, "content", pane.content_region, "scroll_y", pane.scroll_y, "max", pane.max_scroll_y,
              "virtual", pane.virtual_size)
        for wid in ("patch_doc_file_row", "patch_doc_path_input", "patch_doc_controls", "patch_doc_validate_button"):
            w = app.screen.query_one("#" + wid)
            print("PROBE", size, "OUT", wid, w.region)
        for w in pane.query("*"):
            if not w.display or w.id is None:
                continue
            r = w.region
            hit = app.get_widget_at(*r.center)[0] if r.area else None
            inside = pane.region.contains_region(r) if r.area else None
            print("PROBE", size, "IN", w.id, type(w).__name__, r, "inside_pane", inside, "hit", getattr(hit, "id", None))
        for i, line in enumerate(painted_rows(app, app.screen)):
            print("ROW %02d|%s" % (i, line))
        return None

    p.drive(tmp_path, size, body, a2l=defc / "definitions.a2l", image=defc / "definitions.s19")
