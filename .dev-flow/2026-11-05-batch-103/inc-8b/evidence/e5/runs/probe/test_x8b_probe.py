"""X8b E5 security probe (scratch only, never committed to tests/): hostile A2L text in the grid and the cards."""
from dataclasses import replace

import pytest
from rich.cells import cell_len

from s19_app.tui import definition_sheet as ds
from s19_app.tui.screens_directionb.patch_editor import bench_sheet as _bench_sheet  # noqa: F401
from tests.support.b103_inc8_s1 import defc  # noqa: F401

HOSTILE = {
    "wide": "名前" * 40,
    "esc": "A\x1b[2J\x07B\x9b31m",
    "bidi": "‮evil‬",
    "long": "x" * 100_000,
    "markup": "[@click=app.quit]X[/]",
    "nul": "\x00\x00",
    "zwj": "é‍" * 50,
}
KINDS = ["DISPLAY_0001", "ENUM_0001", "MASK_FIELD_0001", "MAP_DEF_0001"]


def _row(case, kind, text):
    d = replace(case["defs"][kind], name=text, unit=text)
    if d.enum_entries:
        d = replace(d, enum_entries=tuple(replace(e, text=text) for e in d.enum_entries))
    overlay = ds.StagedOverlay(case["image"], [])
    return ds.build_row(d, case["a2l"], case["image"], overlay)


@pytest.mark.parametrize("key", sorted(HOSTILE))
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("view", [70, 110, 194])
def test_probe(defc, kind, key, view):
    row = _row(defc, kind, HOSTILE[key])
    widths = ds.sheet_widths(view)
    for selected in (False, True):
        line = ds.row_line(row, widths, selected, None, None, odd=True)
        assert cell_len(line.plain) == ds.GRID_WIDTH, (cell_len(line.plain), line.plain[:80])
        cells = [cell_len(line.plain[:i]) for i, c in enumerate(line.plain) if c == "│"][-7:]
        head = ds.header_line(widths).plain
        assert cells == [cell_len(head[:i]) for i, c in enumerate(head) if c == "│"], line.plain[:160]
    lines = ds.detail_lines(row, None, view, None, 50)
    for shown in lines:
        assert cell_len(shown.plain) == max(ds.GRID_WIDTH, view), (cell_len(shown.plain), shown.plain[:80])
    for text in [line] + lines:
        assert not any(ch in text.plain for ch in "\x00\x07\x1b\x9b"), text.plain[:80]
        for span in text.spans:
            assert "@click" not in str(span.style)
