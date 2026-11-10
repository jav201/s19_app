"""Inspect fixed and scrolled column spans for R-A2L-048/4."""
from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:
    root = Path(sys.argv[1]).resolve()
    scratch = Path(sys.argv[2]).resolve()
    sys.path.insert(0, str(root))
    import s19_app
    from tests.support import b100_projects as projects
    from tests.test_b101_inplace_views import load_case, show_a2l, tag_table

    print(s19_app.__file__)

    async def scenario(app, pilot, log) -> None:
        case = scratch / "case"
        case.mkdir(parents=True, exist_ok=True)
        from tools.synth import make_release_case as gen

        gen.generate(case, 20260001, 1.0)
        await load_case(pilot, app, case, a2l=True)
        await show_a2l(pilot, app)
        table = tag_table(app)
        columns = table.ordered_columns
        raw_x = sum(c.get_render_width(table) for c in columns[:4])
        table.scroll_to(x=raw_x, animate=False)
        await pilot.pause()
        print(f"scroll_x={table.scroll_x} raw_x={raw_x} fixed={table.fixed_columns}")
        print(f"widths={[c.get_render_width(table) for c in columns]}")
        print(f"line={table.render_line(15).text!r}")
        print(f"raw={table.get_row_at(14)[4].plain!r} physical={table.get_row_at(14)[5].plain!r}")

    projects.run_app(scratch, scenario, size=(120, 56))


if __name__ == "__main__":
    main()
