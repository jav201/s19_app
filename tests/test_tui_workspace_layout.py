"""Workspace hex-pane layout tests — batch-17 US-018 (HLR-018).

US-018: the Workspace hex column must show a full 16-byte + ASCII row on ONE
line (it currently wraps/truncates). The MAC/A2L fix (`min-width: 82` on a
two-pane split) does NOT transfer: the Workspace is a THREE-pane layout with two
fixed-width sides (`#ws_left` 22 + `#ws_right` 40), so at a 120-col terminal
(body ~96) a `min-width: 82` floor on `#ws_center` would need 22+82+40=144 and
shove the right context pane off-screen (§6.5 amendment A2). Root cause: the
`#hex_view` `Static` WRAPS to the pane width, so the 81-cell row reflows.

Fix (§6.5 A2): `#hex_view { width: auto }` — the hex view sizes to its content
(one full row, ~81 cells); `#hex_scroll`'s `overflow: auto` then gives a
horizontal scrollbar when the pane is narrower. The row stays on one line and
all three panes remain visible.

AT-018 (black-box, Pilot): drive the live Workspace, load `prg.s19`, render the
hex view, and assert (1) the hex row is laid out on one line and is horizontally
scrollable, and (2) all three panes stay visible (the regression guard against
the rejected min-width approach).

Test -> requirement:
    test_ws_hex_row_on_one_line_and_scrollable   AT-018       RED pre-fix (#hex_view wraps to ~30)
    test_ws_all_three_panes_stay_visible         AT-018 guard  right context pane not pushed off-screen
    test_ws_hex_one_line_holds_in_narrow_regime  AT-018 bdy    80-col narrow regime: one line + no crash
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from s19_app.tui.app import S19TuiApp

_PRG_S19 = Path(__file__).resolve().parent.parent / "examples" / "case_00_public" / "prg.s19"

#: A full Workspace hex row = "> " + "0x%08X  " + 16*"XX " + " |" + 16 ascii + "|"
#: = 81 cells (hexview.py:401-434). The row must lay out on one line >= this.
_FULL_ROW_CELLS = 81


def _install_prg_loaded_file(app: S19TuiApp) -> None:
    """Install the public ``prg.s19`` fixture as ``current_file`` and reveal the panes.

    The Workspace shows an ``EmptyStatePanel`` (hiding the three panes) with no
    ``LoadedFile``, so the layout assertions need a real loaded file — the same
    flip the load pipeline performs (mirrors
    ``tests/test_tui_directionb.py::_install_prg_loaded_file``).
    """
    from s19_app.core import S19File
    from s19_app.tui.services.load_service import build_loaded_s19

    s19 = S19File(str(_PRG_S19))
    app.current_file = build_loaded_s19(_PRG_S19, s19, a2l_path=None, a2l_data=None)
    app._apply_empty_state()


def _ws_hex_dims(tmp_path: Path, size: tuple[int, int]) -> dict[str, int]:
    """Activate the Workspace at ``size``, render the hex view, return geometry.

    Summary:
        Boots a fresh ``S19TuiApp`` under ``App.run_test(size=size)``, switches
        to the Workspace, installs the ``prg.s19`` fixture, renders the hex view,
        and snapshots the geometry that proves the row is on one line and
        scrollable while all three panes stay visible.

    Args:
        tmp_path (Path): Per-test temp dir used as the app ``base_dir``.
        size (tuple[int, int]): ``(width, height)`` terminal size for ``run_test``.

    Returns:
        dict[str, int]: ``narrow`` (1 if ``width-narrow`` set), ``screen_w``,
        ``hex_view_w`` (content width of ``#hex_view``), ``hex_virtual_w``
        (scrollable content width of ``#hex_scroll``), ``hex_viewport_w``,
        ``left_w`` / ``center_w`` / ``right_w`` pane widths, and ``right_edge``
        (``#ws_right`` x + width — must stay within ``screen_w`` to be visible).

    Data Flow:
        ``run_test`` -> ``action_show_screen("workspace")`` ->
        ``_install_prg_loaded_file`` -> ``update_hex_view`` -> ``.region`` reads.

    Dependencies:
        Uses: ``S19TuiApp``, Textual ``App.run_test``.
        Used by: the ``test_ws_*`` cases in this module.
    """

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("workspace")
            _install_prg_loaded_file(app)
            app.update_hex_view()
            await pilot.pause()
            body = app.query_one("#workspace_body")
            hex_view = app.query_one("#hex_view")
            hex_scroll = app.query_one("#hex_scroll")
            right = app.query_one("#ws_right")
            return {
                "narrow": int(body.has_class("width-narrow")),
                "screen_w": app.size.width,
                "hex_view_w": hex_view.region.width,
                "hex_virtual_w": hex_scroll.virtual_size.width,
                "hex_viewport_w": hex_scroll.region.width,
                "left_w": app.query_one("#ws_left").region.width,
                "center_w": app.query_one("#ws_center").region.width,
                "right_w": right.region.width,
                "right_edge": right.region.x + right.region.width,
            }

    return asyncio.run(_drive())


def test_ws_hex_row_on_one_line_and_scrollable(tmp_path: Path) -> None:
    """AT-018 / LLR-018.1 — the hex row lays out on one line and scrolls.

    Intent: at 120 cols the Workspace hex view must render a full 16-byte+ASCII
    row on ONE line (content width >= 81), and `#hex_scroll` must be able to
    scroll horizontally to reach it (scrollable content width >= 81) rather than
    wrapping to the ~30-cell pane. FAILS on the pre-fix tree (`#hex_view` wraps,
    so both widths clamp to ~30) — the captured RED for the fix.
    """
    dims = _ws_hex_dims(tmp_path, (120, 30))

    assert dims["narrow"] == 0, "at 120 cols the fixed-width regime must be active"
    assert dims["hex_view_w"] >= _FULL_ROW_CELLS, (
        f"the hex view must lay a full {_FULL_ROW_CELLS}-cell row on one line "
        f"(width:auto, no wrap), got hex_view width {dims['hex_view_w']} "
        f"(viewport {dims['hex_viewport_w']})"
    )
    assert dims["hex_virtual_w"] >= _FULL_ROW_CELLS, (
        f"#hex_scroll must be horizontally scrollable to a full row "
        f"(virtual width >= {_FULL_ROW_CELLS}), got {dims['hex_virtual_w']} — a "
        f"wrapped view clamps virtual width to the viewport ({dims['hex_viewport_w']})"
    )


def test_ws_all_three_panes_stay_visible(tmp_path: Path) -> None:
    """AT-018 guard / LLR-018.1 — the fix keeps the right context pane on-screen.

    Intent: the rejected `min-width: 82` approach makes `#ws_center` 82 wide,
    pushing `#ws_right` past the viewport edge at 120 cols. The no-wrap+scroll fix
    must instead leave the pane widths intact and the right context pane fully
    visible. Guards against a regression that reintroduces the floor.
    """
    dims = _ws_hex_dims(tmp_path, (120, 30))

    assert dims["left_w"] > 0 and dims["center_w"] > 0 and dims["right_w"] > 0, (
        f"all three panes must have positive width; "
        f"left={dims['left_w']} center={dims['center_w']} right={dims['right_w']}"
    )
    assert dims["right_edge"] <= dims["screen_w"], (
        f"the right context pane must stay within the {dims['screen_w']}-col "
        f"viewport (not pushed off-screen by a min-width floor); right edge at "
        f"{dims['right_edge']}"
    )


def test_ws_hex_one_line_holds_in_narrow_regime(tmp_path: Path) -> None:
    """AT-018 boundary (QC-3) — the one-line+scroll behaviour holds at 80 cols.

    Intent: in the `width-narrow` regime the app must still lay the row on one
    line (content-sized hex view, scrollable) and lay out without raising; the
    fix is regime-independent (no `min-width` floor to misapply).
    """
    dims = _ws_hex_dims(tmp_path, (80, 30))

    assert dims["narrow"] == 1, "at 80 cols the width-narrow regime must be active"
    assert dims["center_w"] > 0, "the center pane must keep a positive width"
    assert dims["hex_view_w"] >= _FULL_ROW_CELLS, (
        f"the hex row must stay on one line in the narrow regime too, got "
        f"hex_view width {dims['hex_view_w']}"
    )
