"""MAC View hex-pane layout tests — batch-05 increment 2 (HLR-002).

Covers the CSS-sizing LLRs added by batch-2026-05-26-batch-05:
  - LLR-002.1 / TC-004 — ``#mac_hex_pane`` is >=82 cols at the comfortable
    (>=120-column) regime, so a full hex row fits without wrapping.
  - LLR-002.2 / TC-005 — ``#mac_hex_scroll`` fills the vertical extent of the
    pane below the title + controls (mirrors the ``#hex_scroll`` rule).
  - LLR-002.3 / TC-006 — the ``width-narrow`` (<120-column) regime is still the
    rule that drives the layout: the pane is ~35 % of the body, not the fixed 82.
  - LLR-002.4 / TC-013 — the records pane keeps a strictly-positive width at
    120 columns so the record list never collapses to zero.

All four drive the live Textual app via ``App.run_test(size=(W, 30))`` and read
``.region`` geometry, matching the established pattern in
``tests/test_tui_directionb.py::test_tc021_*``. The MAC View is activated with
``action_show_screen("mac")``; no file load is required — the two panes exist in
the compose tree regardless of whether a file is loaded.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from s19_app.tui.app import S19TuiApp


def _mac_layout_dims(tmp_path: Path, size: tuple[int, int]) -> dict[str, int]:
    """Activate the MAC View at ``size`` and return the panes' cell geometry.

    Summary:
        Boots a fresh ``S19TuiApp`` under ``App.run_test(size=size)``, switches
        to the MAC screen, and snapshots the cell widths/heights of the hex
        pane, its inner scroll container, the title and controls above the
        scroll, and the records pane.

    Args:
        tmp_path: Per-test temp dir used as the app ``base_dir`` so the
            ``.s19tool/`` workarea is isolated.
        size: ``(width, height)`` terminal size handed to ``run_test``.

    Returns:
        A mapping with keys ``narrow`` (1 if the ``width-narrow`` class is set,
        else 0), ``body_w``, ``hex_w``, ``hex_h``, ``scroll_h``, ``title_h``,
        ``controls_h``, and ``records_w`` — all integer cell counts.

    Data Flow:
        ``run_test`` → ``action_show_screen("mac")`` → ``query_one(...).region``
        reads on the laid-out widget tree.

    Dependencies:
        Uses: ``S19TuiApp``, Textual ``App.run_test``.
        Used by: the four ``test_mac_*`` cases in this module.
    """

    async def _drive() -> dict[str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            app.action_show_screen("mac")
            await pilot.pause()
            body = app.query_one("#workspace_body")
            hex_pane = app.query_one("#mac_hex_pane")
            scroll = app.query_one("#mac_hex_scroll")
            title = app.query_one("#mac_hex_title")
            controls = app.query_one("#mac_hex_controls")
            records = app.query_one("#mac_records_pane")
            return {
                "narrow": int(body.has_class("width-narrow")),
                "body_w": body.region.width,
                "hex_w": hex_pane.region.width,
                "hex_h": hex_pane.region.height,
                "scroll_h": scroll.region.height,
                "title_h": title.region.height,
                "controls_h": controls.region.height,
                "records_w": records.region.width,
            }

    return asyncio.run(_drive())


def test_mac_hex_pane_width_at_wide_terminal(tmp_path: Path) -> None:
    """TC-004 / LLR-002.1 — the hex pane is >=82 cols at 120 columns.

    Intent: the comfortable-regime ``#mac_hex_pane { width: 82 }`` rule must
    win at terminal width 120 so a full hex row (``> `` marker + address + 16
    bytes + ASCII gutter) renders without wrapping. The ``width-narrow`` class
    must NOT be active at exactly 120 columns.
    """
    dims = _mac_layout_dims(tmp_path, (120, 30))

    assert dims["narrow"] == 0, (
        "at 120 cols the comfortable (fixed-width) regime must be active "
        "(width-narrow must be unset)"
    )
    assert dims["hex_w"] >= 82, (
        f"at 120 cols the MAC hex pane must be >=82 cells wide, "
        f"got {dims['hex_w']}"
    )


def test_mac_hex_scroll_fills_pane_height(tmp_path: Path) -> None:
    """TC-005 / LLR-002.2 — the scroll fills the pane below title + controls.

    Intent: ``#mac_hex_scroll { height: 100% }`` must make the inner scroll
    container take all the vertical room left after the ``#mac_hex_title``
    label and the ``#mac_hex_controls`` row that sit above it inside the pane.

    Note on the assertion form: HLR-002's literal pass threshold is
    ``scroll.height == pane.height``, but the MAC pane's compose tree
    (``app.py:1488-1502``) stacks ``#mac_hex_title`` and ``#mac_hex_controls``
    ABOVE ``#mac_hex_scroll`` inside the pane, so the scroll can only ever fill
    the *remaining* height — a strict equality is structurally impossible.
    We therefore assert the robust equivalent: the scroll is non-trivially
    tall, fills the pane height minus the title+controls rows, and is the
    tallest child of the pane. This is the documented softening from the
    increment brief (TC-005 height-equation tradeoff).
    """
    dims = _mac_layout_dims(tmp_path, (120, 30))

    assert dims["scroll_h"] > 1, (
        f"the MAC hex scroll must have a non-trivial height, "
        f"got {dims['scroll_h']}"
    )
    remaining = dims["hex_h"] - (dims["title_h"] + dims["controls_h"])
    assert dims["scroll_h"] >= remaining, (
        f"the MAC hex scroll (h={dims['scroll_h']}) must fill the pane height "
        f"(h={dims['hex_h']}) left after the title (h={dims['title_h']}) and "
        f"controls (h={dims['controls_h']}) rows, i.e. >= {remaining}"
    )
    assert dims["scroll_h"] > dims["title_h"], (
        "the MAC hex scroll must be taller than the title row"
    )
    assert dims["scroll_h"] > dims["controls_h"], (
        "the MAC hex scroll must be taller than the controls row"
    )


def test_mac_hex_pane_narrow_regime_unchanged(tmp_path: Path) -> None:
    """TC-006 / LLR-002.3 — the <120-col proportional regime still drives layout.

    Intent: below the 120-column breakpoint the ``width-narrow`` class must be
    set and the ``#workspace_body.width-narrow #mac_hex_pane { width: 35% }``
    rule must win — NOT the new comfortable-regime fixed 82. This proves the
    batch-05 widening did not leak into the narrow regime.

    Note on the assertion form: the 35 % is proportional to the *body* width,
    not the raw terminal width. At 119 cols the body is ~113 cols, so the pane
    lands at ~39 cols (34.5 % of the body) — not ``round(119 * 0.35) = 42``.
    Asserting against the body width (the form already used by
    ``test_tc021_mac_two_panes_proportional_regime``) is the robust check; the
    raw-terminal ``round(119 * 0.35)`` formula in the brief would be off by 3.
    """
    dims = _mac_layout_dims(tmp_path, (119, 30))

    assert dims["narrow"] == 1, (
        "at 119 cols (<120) the proportional (width-narrow) regime must be "
        "active (width-narrow must be set)"
    )
    hex_pct = 100 * dims["hex_w"] / dims["body_w"]
    assert 31 <= hex_pct <= 39, (
        f"at 119 cols the MAC hex pane must be 35%+/-4 points of the body "
        f"(proportional regime), got {hex_pct:.1f}%"
    )
    assert dims["hex_w"] < 82, (
        f"at 119 cols the comfortable fixed-82 rule must NOT apply, "
        f"got hex pane width {dims['hex_w']}"
    )


def test_mac_records_pane_positive_width_at_wide_terminal(tmp_path: Path) -> None:
    """TC-013 / LLR-002.4 — the records pane keeps a positive width at 120 cols.

    Intent: after LLR-002.1 raised the hex pane to 82 cols, the ``1fr`` records
    pane must still receive a strictly-positive remainder at terminal width 120
    so the record list never collapses to zero width.
    """
    dims = _mac_layout_dims(tmp_path, (120, 30))

    assert dims["records_w"] >= 1, (
        f"at 120 cols the MAC records pane (1fr) must keep a strictly-positive "
        f"width, got {dims['records_w']}"
    )
