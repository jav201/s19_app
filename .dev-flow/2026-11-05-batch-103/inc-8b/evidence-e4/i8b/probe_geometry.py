import pytest
from tests.support.b103_inc9_w import defc_dir, run, need  # noqa: F401


@pytest.mark.parametrize("size", [(118, 54), (80, 24), (220, 60)])
def test_probe(tmp_path, defc_dir, size):
    async def body(app, pilot, panel):
        await pilot.pause()
        sheet = need(panel, "#patch_sheet")
        out = []
        try:
            w = sheet.query_one("#patch_sheet_grid")
        except Exception:
            w = sheet.query_one("#patch_sheet_body")
        node = w
        while node is not None and node is not app:
            out.append((type(node).__name__, node.id, node.region.width, node.content_size.width,
                        getattr(node, "show_vertical_scrollbar", None), getattr(node, "show_horizontal_scrollbar", None),
                        str(node.styles.padding), str(node.styles.border)))
            node = node.parent
        return out
    for row in run(tmp_path, defc_dir, body, size=size):
        print(size, row)
