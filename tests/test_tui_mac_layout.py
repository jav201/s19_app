"""MAC View hex-pane layout tests — batch-05 increment 2 + batch-06 increment 1.

Batch-06 (HLR-001) supersedes the batch-05 fixed-82 / ``width-narrow 35%``
two-regime MAC layout with A2L's flat proportional split plus a full-row
floor: ``#mac_records_pane 4fr``, ``#mac_hex_pane 3fr; min-width: 82``, so
the hex pane width equals ``max(82, round(3/7 * body_w))`` at every width.

Surviving batch-05 coverage:
  - LLR-002.1 — ``#mac_hex_pane`` is >=82 cols at 120 columns (now via the
    ``min-width`` floor instead of the retired fixed ``width: 82``).
  - LLR-002.2 — ``#mac_hex_scroll`` fills the vertical extent of the pane
    below the title + controls (mirrors the ``#hex_scroll`` rule).
  - LLR-002.4 / TC-006 — the records pane keeps a strictly-positive width at
    120 columns so the record list never collapses to zero.

Batch-06 coverage (LLR-001.1-.4):
  - TC-002 / LLR-001.1 — the hex pane grows proportionally (~3/7 of the
    body) at a 250-column terminal, past the old fixed-82 cap.
  - TC-003 / LLR-001.2 — the records pane holds the ~4/7 share and is wider
    than the hex pane where proportional dominates.
  - TC-004 / LLR-001.3 — at 120 columns the ``min-width: 82`` floor, not the
    3/7 proportional share (~41), sizes the hex pane.
  - TC-005 / LLR-001.4 — the floor holds on both sides of the retired
    120-column MAC breakpoint (the ``width-narrow`` MAC rules are deleted).
    The batch-05 narrow-regime test (``hex_w < 82`` at 119 cols) asserted the
    retired ``35%`` regime and was deleted in favor of TC-005.

All tests drive the live Textual app via ``App.run_test(size=(W, H))`` and read
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


def test_mac_hex_pane_proportional_at_wide_terminal(tmp_path: Path) -> None:
    """TC-002 / LLR-001.1 — the hex pane is proportional (3fr) at 250 columns.

    Intent: batch-06 replaces the fixed ``width: 82`` cap with ``width: 3fr``
    mirroring ``#a2l_hex_pane``, so on a terminal wide enough that the 3/7
    proportional share exceeds the 82-cell floor (body >= 192, terminal ~216
    cols) the MAC hex pane GROWS past 82 and holds ~3/7 (~=42.9%) of the
    workspace body — the retired fixed cap would have pinned it at 82.
    """
    dims = _mac_layout_dims(tmp_path, (250, 40))

    assert dims["hex_w"] > 86, (
        f"at 250 cols the MAC hex pane (3fr) must grow past the 82-cell "
        f"floor, got {dims['hex_w']}"
    )
    hex_pct = 100 * dims["hex_w"] / dims["body_w"]
    assert 37 <= hex_pct <= 49, (
        f"at 250 cols the MAC hex pane must be 3/7 (~=42.9%) +/-6 points of "
        f"the body (proportional regime above the floor), got {hex_pct:.1f}% "
        f"(hex={dims['hex_w']}, body={dims['body_w']})"
    )


def test_mac_records_pane_proportional_at_wide_terminal(tmp_path: Path) -> None:
    """TC-003 / LLR-001.2 — the records pane is proportional (4fr) at 250 cols.

    Intent: ``#mac_records_pane`` moves from ``1fr`` (the remainder of a
    fixed-82 hex pane) to ``4fr`` mirroring ``#a2l_tags_pane``, so where the
    proportional split dominates the records pane holds the larger ~4/7
    (~=57.1%) share of the workspace body and stays wider than the hex pane.
    """
    dims = _mac_layout_dims(tmp_path, (250, 40))

    records_pct = 100 * dims["records_w"] / dims["body_w"]
    assert 51 <= records_pct <= 63, (
        f"at 250 cols the MAC records pane must be 4/7 (~=57.1%) +/-6 points "
        f"of the body, got {records_pct:.1f}% "
        f"(records={dims['records_w']}, body={dims['body_w']})"
    )
    assert dims["records_w"] > dims["hex_w"], (
        f"at 250 cols the records pane (4fr) must be wider than the hex pane "
        f"(3fr), got records={dims['records_w']} vs hex={dims['hex_w']}"
    )


def test_mac_hex_pane_floor_at_120(tmp_path: Path) -> None:
    """TC-004 / LLR-001.3 — the ``min-width: 82`` floor sizes the pane at 120.

    Intent: at the 120-column documented minimum the body is ~96 cells, so
    the 3/7 proportional share would be ~41 — narrower than a full hex row.
    The ``min-width: 82`` floor must clamp the ``3fr`` pane up to 82 so a full
    hex row (``> `` marker + address + 16 bytes + ASCII gutter) renders
    without truncation. The second assertion proves the FLOOR, not the
    proportional share, is the rule in effect.
    """
    dims = _mac_layout_dims(tmp_path, (120, 30))

    assert 80 <= dims["hex_w"] <= 86, (
        f"at 120 cols the MAC hex pane must be held at the 82-cell floor "
        f"(80..86), got {dims['hex_w']}"
    )
    share = round(3 / 7 * dims["body_w"])
    assert abs(dims["hex_w"] - share) > 3, (
        f"at 120 cols the hex pane width ({dims['hex_w']}) must come from the "
        f"min-width floor, NOT the 3/7 proportional share "
        f"(~{share} of body={dims['body_w']})"
    )


def test_mac_hex_floor_holds_across_retired_breakpoint(tmp_path: Path) -> None:
    """TC-005 / LLR-001.4 — the floor holds on both sides of the retired
    120-column MAC breakpoint.

    Intent: the ``width-narrow`` MAC rules (``35%`` hex pane below 120 cols)
    are deleted, so the single proportional+floor regime must apply on BOTH
    sides of the former breakpoint: at 121 and 119 cols the 3/7 share is below
    82, so the hex pane is floored to 82 either way — no MAC-rule regime
    switch remains. Note: a residual *body-width* jump at 120 cols persists
    because the workspace activity rail collapses below 120; that is the
    rail's discontinuity, not a MAC selector's, and is out of scope here.
    """
    for size in [(121, 30), (119, 30)]:
        dims = _mac_layout_dims(tmp_path, size)
        assert 80 <= dims["hex_w"] <= 86, (
            f"at {size} the MAC hex pane must be held at the 82-cell floor "
            f"(80..86) — the retired width-narrow 35% regime must NOT apply, "
            f"got {dims['hex_w']} (body={dims['body_w']})"
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
