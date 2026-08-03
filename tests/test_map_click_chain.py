"""batch-67 AC-3 / AC-4 / AC-5 — Memory-Map click semantics split by chain length.

Summary:
    Before batch-67 a SINGLE click on a memory-map region row did two things:
    it populated the ``#map_detail`` inspector *and* posted
    ``MemoryMapPanel.OpenInHexRequested``, which switched the operator to the
    Workspace/hex screen. Browsing regions was therefore a navigation trap —
    you could not look at a region without being moved off the map.

    N4a splits the gestures: **single click inspects, double click navigates.**
    Inspecting is cheap and reversible so it gets the cheap gesture; navigating
    is disruptive so it gets the deliberate one.

    Three oracles:

    - **AC-3** single click populates the inspector and posts NOTHING.
    - **AC-4** double click posts exactly one ``OpenInHexRequested`` carrying
      the region start.
    - **AC-5** is the C-31/C-32 counterfactual: it states the OLD contract
      ("a chain-1 activation navigates") and asserts it is now FALSE. Without
      it, AC-3 could be satisfied by a panel that never navigates at all, and
      nothing in the suite would record that a shipped interaction changed.

    AC-3/AC-4 drive REAL pointer events through ``Pilot.click`` /
    ``Pilot.double_click`` (C-16), so the chain value under test is the one
    Textual actually produces — not a hand-built number that could disagree
    with the framework.

Data Flow:
    - Builds a two-band S19 image, shows the map screen, then clicks region
      rows and reads ``#map_detail_body`` plus the panel's posted messages.

Dependencies:
    Uses:
        - ``s19_app.tui.screens_directionb.MemoryMapPanel`` / ``RegionRow``
    Used by:
        - the batch-67 acceptance gate (AC-3, AC-4, AC-5)
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Callable, List

from s19_app.tui.app import S19TuiApp
from tests.test_tui_directionb import _two_band_loaded, _widget_plain


def _capture_nav(panel: "object", sink: List[int]) -> None:
    """Wrap ``panel.post_message`` so every ``OpenInHexRequested`` lands in ``sink``.

    Args:
        panel (object): The live ``MemoryMapPanel``.
        sink (List[int]): Receives one focus address per navigation message.

    Data Flow:
        - Replaces the bound method; the original is still called so the app
          behaves normally and the test observes rather than suppresses.

    Dependencies:
        Used by:
            - every test in this module
    """
    from s19_app.tui.screens_directionb import MemoryMapPanel

    original = panel.post_message

    def _cap(msg: "object") -> bool:
        if isinstance(msg, MemoryMapPanel.OpenInHexRequested):
            sink.append(msg.focus_address)
        return original(msg)

    panel.post_message = _cap  # type: ignore[method-assign]


async def _settle_band_bar(app: "S19TuiApp", pilot: "object", max_pauses: int = 40):
    """Pause until the band bar's width is stable across two pause boundaries.

    batch-77 (LLR-111.1 / LLR-111.6) makes the strip's segment widths a function
    of the MEASURED container. That measurement does not exist where the widgets
    are built — on a fresh render ``#map_grid`` reports width 0 — so the widths
    settle one frame after the mount. Reading a region after a single pause
    therefore reads a transient: measured at 120x30, one pause reports a
    52-column bar with every segment 1 column wide, while the settled state is a
    50-column bar with segments 25 / 1 / 24. A segment picked from the transient
    is clicked at coordinates that, by click time, belong to a different segment.

    Repeated reads WITHIN one frame are not evidence of settling — the criterion
    is a fixed point across successive ``pause()`` boundaries.
    """
    previous = None
    for _ in range(max_pauses):
        await pilot.pause()
        bars = list(app.query(".map-band-bar"))
        if not bars:
            return 0
        width = bars[0].region.width
        if previous is not None and width == previous:
            return width
        previous = width
    raise AssertionError(
        f"band bar width never settled across {max_pauses} pauses; last {previous}"
    )


async def _map_ready(app: "S19TuiApp", loaded: "object", pilot: "object"):
    """Show the map screen with ``loaded`` installed and return the live panel."""
    from s19_app.tui.screens_directionb import MemoryMapPanel

    await pilot.pause()
    app.current_file = loaded
    app.action_show_screen("map")
    app.update_memory_map()
    await _settle_band_bar(app, pilot)
    return app.query_one("#memory_map_panel", MemoryMapPanel)


def _drive_clicks(
    tmp_path: Path, gesture: Callable, match_text: str = "high/random"
) -> tuple[List[int], str, int]:
    """Run one gesture against a matching region row.

    Args:
        tmp_path (Path): pytest temp dir for the app base.
        gesture (Callable): ``async (pilot, widget) -> None`` — the pointer
            gesture under test.
        match_text (str): Substring identifying the target region row.

    Returns:
        tuple[List[int], str, int]: ``(navigation addresses posted, detail-pane
        text, the clicked row's region_start)``.
    """
    from s19_app.tui.screens_directionb import RegionRow

    loaded = _two_band_loaded(tmp_path)

    async def _run() -> tuple[List[int], str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        posted: List[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            _capture_nav(panel, posted)
            row = next(
                r for r in app.query(RegionRow) if match_text in _widget_plain(r)
            )
            # Scroll the OWNING viewport, not the row's own ``scroll_visible``.
            # batch-77's LLR-111.9 stacks the band row, growing it 4 -> 6 rows at
            # 120x30 (the accepted C-77-k cost), which pushes the region list to
            # the bottom edge of #map_content's 13-row viewport. Measured, the
            # target row then sits on the boundary: ``scroll_visible`` treats it
            # as already visible and does not scroll, but it is not hit-testable
            # — ``get_widget_at`` at its own reported centre returns the
            # container. ``scroll_to_widget(..., top=True)`` brings it genuinely
            # into view, which is also what the operator does.
            app.query_one("#map_content").scroll_to_widget(
                row, animate=False, top=True
            )
            await pilot.pause()
            await gesture(pilot, row)
            await pilot.pause()
            await pilot.pause()
            detail = str(app.query_one("#map_detail_body").render())
            return posted, detail, row.region_start

    return asyncio.run(_run())


def test_ac3_single_click_inspects_and_does_not_navigate(tmp_path: Path) -> None:
    """AC-3: one real click fills the inspector and posts NO navigation.

    batch-77 Inc-8 — this node is ONE HALF of ``AT-B77-10`` (PIN); the other
    half is ``test_ac4_double_click_navigates_to_the_region_start``. What
    ``AT-B77-10`` claims is that the batch-67 N4a mouse SPLIT survives HLR-115:
    single inspects, double navigates. A split is a two-sided claim, so it maps
    to the two existing nodes that already own its two sides rather than to one
    new node that would cover half of it while being labelled as if it covered
    both (QA M-5). Neither node is modified by Inc-8: ``Enter`` posts the same
    ``RegionRow.Activated`` a click posts, with ``chain = 1``, so the keyboard
    adds no second route past the policy site these two nodes gate.
    """
    posted, detail, region_start = _drive_clicks(
        tmp_path, lambda pilot, row: pilot.click(row)
    )

    assert posted == [], (
        f"a SINGLE click must not navigate to the hex view — that is the "
        f"navigation trap N4a removes. Posted focus addresses: {posted}"
    )
    assert f"0x{region_start:08X}" in detail, (
        f"a single click must still populate the inspector for the clicked "
        f"region 0x{region_start:08X}; got detail={detail!r}"
    )


def test_ac4_double_click_navigates_to_the_region_start(tmp_path: Path) -> None:
    """AC-4: one real double click posts exactly one nav at the region start.

    batch-77 Inc-8 — the second half of ``AT-B77-10`` (PIN); see
    ``test_ac3_single_click_inspects_and_does_not_navigate`` for why the claim
    is mapped to two nodes and not one.
    """
    posted, detail, region_start = _drive_clicks(
        tmp_path, lambda pilot, row: pilot.double_click(row)
    )

    assert posted == [region_start], (
        f"a DOUBLE click must post exactly one OpenInHexRequested carrying the "
        f"region start 0x{region_start:08X}; posted={posted}"
    )
    assert f"0x{region_start:08X}" in detail, (
        "a double click must ALSO leave the inspector populated, so returning "
        f"to the map shows the selection; got detail={detail!r}"
    )


def test_ac5_the_old_single_click_navigates_contract_is_now_false(
    tmp_path: Path,
) -> None:
    """AC-5 counterfactual: the pre-batch-67 contract must NOT hold any more.

    This is the C-31/C-32 obligation for changing a SHIPPED interaction. It
    states the old rule positively — "a chain-1 activation posts
    OpenInHexRequested" — and requires it to be false now. Run against
    ``73e3fb9`` this assertion FAILS (the old tree navigates on chain 1); run
    against this tree it passes. Without it, ``test_ac3`` alone cannot
    distinguish "navigation moved to double-click" from "navigation was
    deleted", and AC-4 alone cannot distinguish "the split works" from "every
    chain length navigates".
    """
    from s19_app.tui.screens_directionb import RegionRow

    loaded = _two_band_loaded(tmp_path)

    async def _run() -> tuple[List[int], List[int]]:
        app = S19TuiApp(base_dir=tmp_path)
        # ONE capture wrapper, sliced by position. Installing a second wrapper
        # would nest it over the first, so the chain-2 message would also land
        # in the chain-1 bucket and the counterfactual would report a phantom
        # regression (observed while writing this test).
        posted: List[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            row = next(iter(app.query(RegionRow)))

            _capture_nav(panel, posted)
            panel.on_region_row_activated(
                RegionRow.Activated(row.region_start, row.region_end, chain=1)
            )
            after_chain1 = list(posted)
            panel.on_region_row_activated(
                RegionRow.Activated(row.region_start, row.region_end, chain=2)
            )
            return after_chain1, posted[len(after_chain1) :]

    chain1, chain2 = asyncio.run(_run())

    assert chain1 == [], (
        "REGRESSION to the pre-batch-67 behaviour: a chain-1 (single) "
        f"activation navigated to hex. Posted: {chain1}"
    )
    assert len(chain2) == 1, (
        "the split must not have removed navigation altogether — a chain-2 "
        f"activation must still navigate exactly once. Posted: {chain2}"
    )


def test_ac6_band_segment_single_click_inspects_its_own_run(tmp_path: Path) -> None:
    """AC-6: a click on a band-strip segment inspects THAT run, without navigating.

    The strip was inert decoration before batch-67 N4b. This asserts the segment
    carries the right window — the inspector must show the segment's OWN
    ``region_start``, not merely "some region" — which is what distinguishes a
    correctly-threaded address from a segment that just forwards the first run.

    Runs at 120x30 like the rest of this module. It ran at 160x48 until
    batch-77: the strip was laid out against a fixed 60-column constant while
    its container was ``width: 1fr``, so at 120x30 the bar rendered only 21
    columns and every segment beyond it was clipped — invisible, and therefore
    unclickable. batch-77 (LLR-111.1/.7/.9) reconciled the two, so a non-first
    segment is now genuinely reachable at the regime this module actually
    tests, which is where the clickability needed covering.
    """
    from s19_app.tui.screens_directionb import BandSegment

    loaded = _two_band_loaded(tmp_path)

    async def _run() -> tuple[List[int], str, int]:
        app = S19TuiApp(base_dir=tmp_path)
        posted: List[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            _capture_nav(panel, posted)
            bar = app.query_one(".map-band-bar")
            segments = [
                s
                for s in app.query(BandSegment)
                if bar.region.contains_region(s.region)
            ]
            assert len(segments) >= 2, (
                "this test needs a reachable NON-first segment; only "
                f"{len(segments)} segment(s) fit inside the bar"
            )
            # The LAST reachable segment, so a handler that always reports the
            # first run cannot pass by coincidence.
            target = segments[-1]
            await pilot.click(target)
            await pilot.pause()
            await pilot.pause()
            detail = str(app.query_one("#map_detail_body").render())
            return posted, detail, target.region_start

    posted, detail, seg_start = asyncio.run(_run())

    assert posted == [], (
        f"a single click on a band segment must inspect, not navigate; "
        f"posted={posted}"
    )
    assert f"0x{seg_start:08X}" in detail, (
        f"the inspector must show the CLICKED segment's own run "
        f"0x{seg_start:08X}; got detail={detail!r}"
    )


def test_ac6_band_segment_double_click_opens_its_run_in_hex(
    tmp_path: Path,
) -> None:
    """AC-6: double-clicking a band segment navigates to that run's start.

    120x30 for the same reason as the single-click test above.
    """
    from s19_app.tui.screens_directionb import BandSegment

    loaded = _two_band_loaded(tmp_path)

    async def _run() -> tuple[List[int], int]:
        app = S19TuiApp(base_dir=tmp_path)
        posted: List[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            _capture_nav(panel, posted)
            bar = app.query_one(".map-band-bar")
            target = [
                s
                for s in app.query(BandSegment)
                if bar.region.contains_region(s.region)
            ][-1]
            await pilot.double_click(target)
            await pilot.pause()
            await pilot.pause()
            return posted, target.region_start

    posted, seg_start = asyncio.run(_run())

    assert posted == [seg_start], (
        f"a double click on a band segment must post exactly one "
        f"OpenInHexRequested at 0x{seg_start:08X}; posted={posted}"
    )


def test_ac6_band_segments_do_not_widen_region_row_queries(
    tmp_path: Path,
) -> None:
    """AC-6 blast-radius guard: ``query(RegionRow)`` must not pick up segments.

    ``BandSegment`` is deliberately a SIBLING of ``RegionRow`` rather than a
    subclass, because Textual's type query matches subclasses — subclassing
    would have silently added one widget per band run to every existing
    ``app.query(RegionRow)`` call site, including the ``N sym`` parsing in
    ``tests/test_tui_map_big.py``. This pins that decision so a later
    "simplification" to a subclass fails here instead of in unrelated suites.
    """
    from s19_app.tui.screens_directionb import BandSegment, RegionRow

    loaded = _two_band_loaded(tmp_path)

    async def _run() -> tuple[int, int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await _map_ready(app, loaded, pilot)
            rows = list(app.query(RegionRow))
            segs = list(app.query(BandSegment))
            overlap = len([w for w in segs if isinstance(w, RegionRow)])
            return len(rows), len(segs), overlap

    row_count, seg_count, overlap = asyncio.run(_run())

    assert seg_count > 0, "the fixture must render at least one band segment"
    assert row_count > 0, "the fixture must render at least one region row"
    assert overlap == 0, (
        f"BandSegment must NOT be a RegionRow subclass — {overlap} of "
        f"{seg_count} segments matched query(RegionRow), which would corrupt "
        f"every existing region-row count assertion"
    )


def test_ac6_gap_hatch_segments_are_not_clickable(tmp_path: Path) -> None:
    """A click on an unmapped gap hatch is inert (LLR-045C.3, preserved).

    Guards the boundary N4b (Inc-4) is about to move: band-strip segments become
    clickable, but the ``╱`` hatch marking an UNMAPPED gap must stay inert —
    there is no region behind it to inspect or open.
    """
    loaded = _two_band_loaded(tmp_path)

    async def _run() -> tuple[int, int]:
        app = S19TuiApp(base_dir=tmp_path)
        posted: List[int] = []
        async with app.run_test(size=(120, 30)) as pilot:
            panel = await _map_ready(app, loaded, pilot)
            _capture_nav(panel, posted)
            gaps = list(app.query(".map-band-gap"))
            for gap in gaps:
                gap.scroll_visible(animate=False)
                await pilot.pause()
                await pilot.double_click(gap)
                await pilot.pause()
            return len(gaps), len(posted)

    gap_count, nav_count = asyncio.run(_run())

    assert nav_count == 0, (
        f"clicking an unmapped gap hatch must never navigate; {gap_count} gap "
        f"segment(s) produced {nav_count} navigation message(s)"
    )
