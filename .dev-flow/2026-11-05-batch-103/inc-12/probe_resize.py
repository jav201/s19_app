"""Inspect the tag cell and render caches through a 220 -> 80 -> 220 resize."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    scratch = Path(sys.argv[2]).resolve()
    sys.path.insert(0, str(root))
    import s19_app
    from tests.test_b103_inc12_tag_table import (
        _explore,
        _geom,
        _painted_lines,
        _painted_tag_cell,
        _settle,
        page_long,
    )

    print(s19_app.__file__)

    async def check(app, pilot, table) -> None:
        calls = []
        original = app._repaint_a2l_tag_cells

        def counted():
            calls.append(1)
            return original()

        app._repaint_a2l_tag_cells = counted
        await pilot.resize_terminal(80, 54)
        await _settle(pilot, 10)
        await pilot.resize_terminal(220, 60)
        await _settle(pilot, 10)
        geom = _geom(table)
        print(f"repaint_calls={len(calls)} geom={geom}")
        print(f"stored={table.get_row_at(0)[2].plain!r}")
        print(f"painted_tag={_painted_tag_cell(table, geom, 0)!r}")
        print(f"line={_painted_lines(table)[1]!r}")
        column = table.ordered_columns[2]
        print(f"content_width={column.content_width} render_width={column.get_render_width(table)}")
        table.notify_style_update()
        await _settle(pilot, 10)
        print(f"after_manual_notify={_painted_tag_cell(table, _geom(table), 0)!r}")
        print(f"after_manual_line={_painted_lines(table)[1]!r}")

    _explore(scratch, page_long(48), (220, 60), check)


if __name__ == "__main__":
    main()
