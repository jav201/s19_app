"""N1 (legend scoped per active screen) + N2 (width-aware activity-log cap).

N1: the Legend modal renders only the LEGEND_TABLE section(s) the active rail
screen paints — A2L→A2L, MAC→MAC, Issues→Issues — and falls back to the full
table on a genuinely unmapped screen (`flow`). Row colours still round-trip
through the frozen SEVERITY_CLASS_MAP.

N8 (AMD-4) amended two of these: Map now renders the entropy band key (not the
LEGEND_TABLE["Hex"] severity rows), and Workspace is explicitly mapped to `()`
(example-only) instead of falling back to the full table — so the full-table
fallback assertion moved from Workspace to `flow`.

N2: `_append_log_line` caps to the app width (was a fixed 50), so long
`.s19tool/workarea/…` paths render untruncated at a wide viewport.

RED pre-fix: the legend renders all four sections from every screen; the log
line clips at 50 chars regardless of width.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Label

from s19_app.tui.app import S19TuiApp
from s19_app.tui.screens import LegendScreen


def _artifact_headings(screen: LegendScreen) -> list[str]:
    return [
        lbl.render().plain
        for lbl in screen.query("#legend_body .legend-artifact")
    ]


async def _open_legend_on(app: S19TuiApp, pilot, screen_key: str) -> LegendScreen:
    app.action_show_screen(screen_key)
    await pilot.pause()
    app.action_show_legend()
    await pilot.pause()
    assert isinstance(app.screen, LegendScreen), (
        f"legend did not open on {screen_key}"
    )
    return app.screen


# ---------------------------------------------------------------------------
# N1 — legend scoped to the active screen
# ---------------------------------------------------------------------------

def test_n1_legend_scoped_per_screen(tmp_path: Path) -> None:
    async def _drive() -> dict[str, list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        out: dict[str, list[str]] = {}
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for key in ("a2l", "mac", "issues", "map"):
                legend = await _open_legend_on(app, pilot, key)
                out[key] = _artifact_headings(legend)
                app.pop_screen()
                await pilot.pause()
        return out

    headings = asyncio.run(_drive())
    assert headings["a2l"] == ["A2L"], headings["a2l"]
    assert headings["mac"] == ["MAC"], headings["mac"]
    assert headings["issues"] == ["Issues"], headings["issues"]
    # N8 AMD-4: Map now renders the entropy band key (header "Entropy bands"),
    # not the LEGEND_TABLE["Hex"] severity/overlay rows.
    assert headings["map"] == ["Entropy bands"], headings["map"]
    assert "Hex" not in headings["map"], headings["map"]


def test_n1_workspace_is_example_only(tmp_path: Path) -> None:
    """N8 AMD-4: Workspace is explicitly mapped to `()` — example-only. It
    renders the N8 example card (≥1 `legend-card-sub` row) and ZERO severity/band
    key rows (no `legend-artifact` header, no `legend-row`), never the old
    full-table fallback."""

    async def _drive() -> tuple[list[str], int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend_on(app, pilot, "workspace")
            headings = _artifact_headings(legend)
            key_rows = len(legend.query("#legend_body .legend-row"))
            card_subs = len(legend.query("#legend_body .legend-card-sub"))
            return headings, key_rows, card_subs

    headings, key_rows, card_subs = asyncio.run(_drive())
    assert headings == [], headings  # example-only: no artifact headers
    assert key_rows == 0, f"workspace must render no key rows, got {key_rows}"
    assert card_subs >= 1, "workspace must render its example card"


def test_n1_unmapped_screen_shows_full_table(tmp_path: Path) -> None:
    """AC-3 fallback re-pointed (AMD-4): `flow` stays genuinely unmapped in
    `_SCREEN_LEGEND_SECTIONS`, so opening the legend there shows every section
    (view_key has no example card and `sections` is `None`)."""

    async def _drive() -> list[str]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend_on(app, pilot, "flow")
            return _artifact_headings(legend)

    headings = asyncio.run(_drive())
    # AC-3 fallback: an unmapped screen shows every section (never empty).
    assert set(headings) == {"A2L", "MAC", "Issues", "Hex"}, headings


def test_n1_rows_keep_frozen_sev_class(tmp_path: Path) -> None:
    async def _drive() -> list[list[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend_on(app, pilot, "a2l")
            return [list(lbl.classes) for lbl in legend.query("#legend_body .legend-row")]

    rows = asyncio.run(_drive())
    assert rows, "no legend rows rendered on the A2L legend"
    frozen_sev = {"sev-ok", "sev-warning", "sev-error", "sev-neutral"}
    # AC-4: every row still carries a frozen sev-* class (or none for White,
    # which maps to no severity) — never a non-frozen class.
    for classes in rows:
        sev = [c for c in classes if c.startswith("sev-")]
        assert all(c in frozen_sev for c in sev), classes


# ---------------------------------------------------------------------------
# N2 — width-aware activity-log cap
# ---------------------------------------------------------------------------

_LONG_PATH = ".s19tool/workarea/my_project/reports/20260723T101500Z-report.md"


def _log_line_4(app: S19TuiApp) -> str:
    return app.query_one("#log_line_4", Label).render().plain


def test_n2_long_path_untruncated_at_wide_viewport(tmp_path: Path) -> None:
    assert len(_LONG_PATH) > 50  # the old cap would clip this

    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(200, 50)) as pilot:
            await pilot.pause()
            app._append_log_line(_LONG_PATH)
            await pilot.pause()
            return _log_line_4(app)

    line = asyncio.run(_drive())
    assert line == _LONG_PATH, (
        f"AC-5: the full path must survive at a wide viewport, got {line!r}"
    )


def test_n2_line_bounded_at_narrow_viewport(tmp_path: Path) -> None:
    async def _drive() -> str:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app._append_log_line("Z" * 300)  # far longer than any width
            await pilot.pause()
            return _log_line_4(app)

    line = asyncio.run(_drive())
    # AC-6: bounded to the app width (80), never unbounded.
    assert len(line) == 80, f"expected width-bounded (80), got {len(line)}"
