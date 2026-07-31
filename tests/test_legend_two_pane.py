"""batch-72 — Legend modal Variant B: the two-pane body (US-072-2).

The shipped modal stacked the ~29-row example card ABOVE the colour key inside a
single scrolling ``#legend_body``, so the key the operator opened the modal for
sat 18 content rows below the fold (00-measurements M-2, shipped baseline).
Variant B splits the body into two independently scrollable panes — example card
left, colour key right — inside the PRESERVED ``#legend_body`` wrapper.

Nodes in this file:

- **AT-216** (HLR-072-5) — the wide regime: the MAC ``Pale yellow`` key row is
  inside the key pane's first screenful at ``scroll_offset 0``, the key pane is
  inside the body, and the key pane does not scroll at all.
- **AT-218** (HLR-072-7) — labelled a **REGRESSION PIN, not a gate**: its subject
  (``legend.py``'s data pipeline) is *unchanged* by this batch, so it is
  invariant under the change. It is kept because it is the only node that would
  catch an accidental data-layer edit or a C-38 emptied query.
- **AT-217** (HLR-072-6) — the floor regime at 80x24: the panes stack key ABOVE
  card, the card keeps a usable height, and the whole key is reachable by
  scrolling.
- **TC-515** — pane ids + per-pane widget counts vs M-6.
- **TC-517** — the ``legend-narrow`` class AND the pane document order both flip
  at ``_LEGEND_NARROW_WIDTH``, in both directions.
- **TC-518** — no ``height: auto`` on the key pane (the degenerate regime).
- **TC-516** — ``#legend_body`` is the two-pane WRAPPER, and all 9 shipped
  ``#legend_body``-rooted query sites still resolve as their own tests expect.
- **TC-519** — ``s19_app/tui/legend.py`` is byte-identical to ``origin/main``
  (LLR-072-7.1: the data layer is reused, never edited).

**AT-216 clause 4 — oracle mutation (C-32 / project engineering-rules).**
Executed at the Inc-1 gate rather than encoded, since a permanently-mutated
oracle is not an oracle: ``#legend_key_pane`` was given ``display: none`` inside
``_measure_key_pane`` and AT-216 went RED — on **clause 2b**, the
body-contains-pane arm added at the Phase-2 re-gate::

    AssertionError: the key pane Region(x=0, y=0, width=0, height=0) is not
    inside #legend_body Region(x=6, y=6, width=107, height=15)

Worth stating plainly: clauses 1 and 2a are BLIND to that mutation, because a
``display: none`` pane collapses the pane AND its rows to ``Region(0,0,0,0)``,
and a zero region trivially contains a zero region. Clause 2b is the only arm
with a tooth here — the re-gate's reason for adding it is confirmed by execution.
Full transcript in
``.dev-flow/2026-07-30-batch-72/03-increments/increment-001.md``.

Geometry is read from measured ``region``s, never from the requested size tuple
(``run_test(size=(120,30))`` yields ``screen.size == Size(118, 28)``).
"""

from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from textual.css.scalar import Unit
from textual.geometry import Offset
from textual.widgets import Static

import s19_app
from s19_app.tui.app import S19TuiApp
from s19_app.tui.legend import LEGEND_TABLE
from s19_app.tui.screens import _LEGEND_NARROW_WIDTH, LegendScreen


# --------------------------------------------------------------------------- #
# Shared pilot helper — the legend is always opened through the SHIPPED surface
# (`k`, the ratified binding — C-16: never a `.focus()` proxy).
# --------------------------------------------------------------------------- #
async def _open_legend(app: S19TuiApp, pilot, view_key: str) -> LegendScreen:
    """
    Summary:
        Show ``view_key``'s rail screen and open the Legend modal through the
        real ``k`` binding.

    Args:
        app (S19TuiApp): The app under test.
        pilot: The Textual ``run_test`` pilot driving the keypress.
        view_key (str): The rail screen key (``mac`` / ``map`` / ``a2l`` / …).

    Returns:
        LegendScreen: The pushed modal.

    Data Flow:
        - Switches the rail screen, clears focus (so ``k`` is not swallowed by a
          filter input), presses ``k``, and asserts the modal is on top.

    Dependencies:
        Used by:
            - every AT/TC in this module
    """
    app.action_show_screen(view_key)
    await pilot.pause()
    app.set_focus(None)  # the operator is not typing in a filter field
    await pilot.press("k")
    await pilot.pause()
    assert isinstance(app.screen, LegendScreen), (
        f"'k' did not open the Legend on {view_key!r}: {type(app.screen).__name__}"
    )
    return app.screen


def _widget_text(widget) -> str:
    """Plain text of a rendered legend row (``Content`` on 8.2.8, str-able)."""
    rendered = widget.render()
    return getattr(rendered, "plain", str(rendered))


# --------------------------------------------------------------------------- #
# AT-216 (HLR-072-5) — wide regime, mac view, 120x30.
# --------------------------------------------------------------------------- #
#: The MAC warning meaning, read from the shipped table — never a literal copy.
_MAC_WARNING_MEANING: str = LEGEND_TABLE["MAC"]["Pale yellow"][1]


def _measure_key_pane(tmp_path: Path) -> Dict[str, object]:
    """
    Summary:
        Drive the mac Legend at 120x30 and measure AT-216's four observables:
        the ``sev-warning`` key row's text and region, the key pane's region /
        scroll state, and the body region.

    Args:
        tmp_path (Path): pytest tmp dir used as the app's ``base_dir``.

    Returns:
        Dict[str, object]: ``row_text``, ``row_in_key_pane``,
        ``key_pane_in_body``, ``key_scroll_offset``, ``key_max_scroll_y``,
        ``n_warning_rows`` — primitives, so a failure prints a readable value.

    Data Flow:
        - Opens the modal through ``k``; anchors the key row on its
          ``{legend-row, sev-warning}`` CLASSES inside ``#legend_key_pane``
          (Q-4: the bare literal ``Pale yellow`` also appears in a card caption,
          so the string alone does not disambiguate the panes).
        - Reads region containment off the PAINTED regions (C-32) — the
          rendered text is geometry-blind and stays True on a pane rendered
          entirely off-dialog.

    Dependencies:
        Used by:
            - test_at216_key_pane_shows_warning_row_without_scrolling
    """

    async def _drive() -> Dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")
            body = legend.query_one("#legend_body")
            card_pane = legend.query_one("#legend_card_pane")
            key_pane = legend.query_one("#legend_key_pane")
            rows = list(legend.query("#legend_key_pane .legend-row.sev-warning"))
            if len(rows) != 1:
                return {"n_warning_rows": len(rows)}
            row = rows[0]
            return {
                "n_warning_rows": 1,
                "row_text": _widget_text(row),
                "row_in_key_pane": key_pane.region.contains_region(row.region),
                "key_pane_in_body": body.region.contains_region(key_pane.region),
                "key_scroll_offset": key_pane.scroll_offset,
                "key_max_scroll_y": key_pane.max_scroll_y,
                "key_region": key_pane.region,
                "body_region": body.region,
                "card_region": card_pane.region,
                # clause 0 — SIDE BY SIDE, card left. The defining property of
                # the wide regime, and the one nothing else observes.
                "key_right_of_card": key_pane.region.x >= card_pane.region.right,
                "panes_share_a_row": key_pane.region.y == card_pane.region.y,
            }

    return asyncio.run(_drive())


def test_at216_key_pane_shows_warning_row_without_scrolling(tmp_path: Path) -> None:
    """AT-216 — at 120x30 the mac colour key is visible beside the card.

    Five clauses, each failing on a different cause:

    0. the panes are SIDE BY SIDE with the card left — ``key.region.x >=
       card.region.right`` and both panes on the same ``region.y``. This is the
       defining property of the wide regime and every other clause is blind to
       it: an independent review removed the ``#legend_dialog.legend-narrow``
       prefix from the narrow rules, collapsing 120x30 into a VERTICAL stack
       (card ``Region(6,6,107,7)``, key ``Region(6,13,107,8)``), and all eight
       tests in this module still passed — containment and ordering are equally
       true of a stack. Swapping ``3fr``/``2fr`` was likewise unobserved;
    1. the key row is anchored on its ``{legend-row, sev-warning}`` classes
       INSIDE ``#legend_key_pane`` and CONTAINS the shipped meaning. Containment,
       not equality: the row is built ``f"{classification} — {meaning}"``
       (``screens.py``), so ``==`` would false-fail a correct implementation;
    2. region containment on the painted regions — the row sits inside the key
       pane at ``scroll_offset == (0, 0)``, AND the key pane sits inside
       ``#legend_body``. Clause 2b is not redundant: every other clause is
       relative to the pane, so all of them pass with the pane rendered entirely
       off-dialog (a CSS-specificity slip put it at ``x=113``, outside a body
       spanning ``[6,113)``, and AT-216 stayed green);
    3. the CAUSE, not only the symptom: the key pane does not scroll at all.
       Measured budget is 14 key rows in a 15-row pane — ONE row of slack — so
       this clause fails on budget exhaustion before the symptom appears.

    (Clause 4, the oracle mutation, is executed at the increment gate — see this
    module's docstring.)
    """
    m = _measure_key_pane(tmp_path)

    # clause 0 — side by side, card left. Nothing else in this module sees it.
    assert m["key_right_of_card"], (
        "the wide regime must place the key pane to the RIGHT of the card pane; "
        f"key={m['key_region']} card={m['card_region']} — a vertical stack here "
        "means the narrow rules are winning at 120 cols (unprefixed selectors)"
    )
    assert m["panes_share_a_row"], (
        "the two panes must start on the same row in the wide regime; "
        f"key={m['key_region']} card={m['card_region']}"
    )

    # clause 1 — the anchor resolves, and it resolves uniquely.
    assert m["n_warning_rows"] == 1, (
        "expected exactly one sev-warning key row in the key pane, got "
        f"{m['n_warning_rows']}"
    )
    assert _MAC_WARNING_MEANING in m["row_text"], (
        f"key row {m['row_text']!r} does not carry the shipped MAC warning "
        f"meaning {_MAC_WARNING_MEANING!r}"
    )

    # clause 2 — painted geometry, both directions.
    assert m["key_scroll_offset"] == Offset(0, 0), (
        f"the key pane must be at rest, got {m['key_scroll_offset']}"
    )
    assert m["row_in_key_pane"], (
        "the warning key row is not inside the key pane's painted region "
        f"(key={m['key_region']})"
    )
    assert m["key_pane_in_body"], (
        f"the key pane {m['key_region']} is not inside #legend_body "
        f"{m['body_region']} — it is rendering off-dialog"
    )

    # clause 3 — the cause: the whole key fits, so nothing has to be scrolled.
    assert m["key_max_scroll_y"] == 0, (
        "the key pane must fit its content without scrolling (measured budget "
        f"is 14 rows in 15), got max_scroll_y={m['key_max_scroll_y']}"
    )


# --------------------------------------------------------------------------- #
# TC-515 — pane ids + per-pane widget counts vs 00-measurements M-6.
# --------------------------------------------------------------------------- #
#: ``view_key -> (card widgets, key widgets)`` — M-6, re-executed at Inc-1.
_M6_PANE_COUNTS: Dict[str, Tuple[int, int]] = {"mac": (17, 6), "map": (20, 7)}


def test_tc515_panes_hold_the_unmodified_render_output(tmp_path: Path) -> None:
    """TC-515 — both panes resolve and hold exactly the widgets
    ``_render_card()`` / ``_render_key()`` return (M-6: mac 17/6, map 20/7).

    A count mismatch means the split reconstructed rows instead of re-parenting
    them (LLR-072-7.1 forbids reconstruction).
    """

    async def _drive() -> Dict[str, Tuple[int, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        out: Dict[str, Tuple[int, int]] = {}
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for view_key in _M6_PANE_COUNTS:
                legend = await _open_legend(app, pilot, view_key)
                out[view_key] = (
                    len(legend.query_one("#legend_card_pane").children),
                    len(legend.query_one("#legend_key_pane").children),
                )
                app.pop_screen()
                await pilot.pause()
        return out

    counts = asyncio.run(_drive())
    assert counts == _M6_PANE_COUNTS, (
        f"pane widget counts drifted from the M-6 measurement: {counts}"
    )


# --------------------------------------------------------------------------- #
# TC-516 — `#legend_body` is the WRAPPER, and the 9 shipped descendant query
# sites still resolve. C-38: a narrowed query that quietly empties still passes
# `all(...)` / `assert not …` at its own call site, so the census is explicit.
# --------------------------------------------------------------------------- #
#: ``(site, view_key, selector, expect_non_empty)`` — the 9 shipped
#: ``#legend_body``-rooted query sites, each probed on a view its OWN test drives.
#: ``test_legend_scope_and_logwidth.py:88`` is the one site whose own assertion is
#: ``== 0`` (workspace is example-only), so it is recorded as expecting empty;
#: that selector's resolvability is proven by site ``:121`` on the a2l view.
_LEGEND_BODY_QUERY_SITES: Tuple[Tuple[str, str, str, bool], ...] = (
    ("test_legend_n8.py:284", "mac", "#legend_body Static", True),
    ("test_legend_n8.py:387", "issues", "#legend_body Static", True),
    (
        "test_legend_scope_and_logwidth.py:34",
        "mac",
        "#legend_body .legend-artifact",
        True,
    ),
    (
        "test_legend_scope_and_logwidth.py:88",
        "workspace",
        "#legend_body .legend-row",
        False,
    ),
    (
        "test_legend_scope_and_logwidth.py:89",
        "workspace",
        "#legend_body .legend-card-sub",
        True,
    ),
    (
        "test_legend_scope_and_logwidth.py:121",
        "a2l",
        "#legend_body .legend-row",
        True,
    ),
    ("test_tui_legend.py:60", "mac", "#legend_body Static", True),
    ("test_tui_legend.py:338", "flow", "#legend_body Label", True),
    ("test_tui_legend.py:407", "flow", "#legend_body Label", True),
)


def _census_legend_body_sites(tmp_path: Path) -> List[Tuple[str, int]]:
    """
    Summary:
        Resolve every shipped ``#legend_body``-rooted selector on the view its
        own test drives, and report the match count per site.

    Args:
        tmp_path (Path): pytest tmp dir used as the app's ``base_dir``.

    Returns:
        List[Tuple[str, int]]: ``(site, match_count)`` in
        ``_LEGEND_BODY_QUERY_SITES`` order.

    Data Flow:
        - Opens the modal once per distinct view and runs that view's selectors.

    Dependencies:
        Used by:
            - test_tc516_legend_body_is_the_two_pane_wrapper
            - test_at218_pipeline_preserved (clause 3)
    """

    async def _drive() -> List[Tuple[str, int]]:
        app = S19TuiApp(base_dir=tmp_path)
        counts: Dict[str, int] = {}
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            for view_key in dict.fromkeys(s[1] for s in _LEGEND_BODY_QUERY_SITES):
                legend = await _open_legend(app, pilot, view_key)
                for site, site_view, selector, _ in _LEGEND_BODY_QUERY_SITES:
                    if site_view == view_key:
                        counts[site] = len(legend.query(selector))
                app.pop_screen()
                await pilot.pause()
        return [(site, counts[site]) for site, _, _, _ in _LEGEND_BODY_QUERY_SITES]

    return asyncio.run(_drive())


def test_tc516_legend_body_is_the_two_pane_wrapper(tmp_path: Path) -> None:
    """TC-516 — ``#legend_body`` survives as the wrapper holding the two panes,
    in the WIDE order (card first in compose), and every shipped descendant
    query site still resolves the way its own test expects."""

    async def _drive() -> Tuple[List[str], bool, bool]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")
            body = legend.query_one("#legend_body")
            return (
                [child.id for child in body.children],
                bool(legend.query("#legend_body #legend_card_pane")),
                bool(legend.query("#legend_body #legend_key_pane")),
            )

    child_ids, card_is_descendant, key_is_descendant = asyncio.run(_drive())
    assert child_ids == ["legend_card_pane", "legend_key_pane"], (
        f"#legend_body must wrap exactly the two panes, card first: {child_ids}"
    )
    assert card_is_descendant and key_is_descendant

    census = _census_legend_body_sites(tmp_path)
    expected = {site: non_empty for site, _, _, non_empty in _LEGEND_BODY_QUERY_SITES}
    for site, count in census:
        if expected[site]:
            assert count > 0, f"{site} resolves 0 widgets through #legend_body"
        else:
            assert count == 0, f"{site} expects an empty result, got {count}"

    # C-38 second arm: every DISTINCT selector must resolve somewhere, so the one
    # site whose own expectation is empty cannot hide a globally-broken selector.
    resolved = {
        selector
        for (site, count), (_, _, selector, _) in zip(census, _LEGEND_BODY_QUERY_SITES)
        if count > 0
    }
    all_selectors = {s[2] for s in _LEGEND_BODY_QUERY_SITES}
    assert resolved == all_selectors, (
        f"these #legend_body selectors resolve nowhere: {all_selectors - resolved}"
    )


# --------------------------------------------------------------------------- #
# AT-218 (HLR-072-7) — REGRESSION PIN, NOT A GATE.
# Its declared subject is the UNCHANGED data pipeline, so it is invariant under
# this batch's change. Labelled so nobody mistakes it for the acceptance gate.
# --------------------------------------------------------------------------- #
def test_at218_pipeline_preserved_regression_pin(tmp_path: Path) -> None:
    """AT-218 (PIN) — the reorganized modal reuses the shipped data pipeline.

    1. mac: ``#legend_mac_warning_sample`` still renders, still in the CARD pane,
       with its inline orange read off ``render().spans`` — NOT ``render_line``,
       which returns the theme foreground ``#e9e9e9`` (project C-37) — and
       coupled to the live ``app`` style, never a hex literal;
    2. map: the band-key rows render in the KEY pane and still report
       ``_render_markup is False`` (they read ``[lo,hi)`` — a literal bracket);
    3. all 9 ``#legend_body``-rooted sites resolve as their own tests expect
       (shares TC-516's census helper).
    """
    from s19_app.tui.app import _SEVERITY_TO_RICH_STYLE
    from s19_app.tui.screens import _MAC_WARNING_SAMPLE_STYLE
    from s19_app.validation import ValidationSeverity

    warning_style = _SEVERITY_TO_RICH_STYLE[ValidationSeverity.WARNING]
    assert _MAC_WARNING_SAMPLE_STYLE == warning_style

    async def _drive() -> Tuple[set, bool, List[bool], List[bool]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(120, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")
            sample = legend.query_one("#legend_mac_warning_sample", Static)
            content = sample.render()
            spans = {span.style for span in getattr(content, "spans", [])}
            in_card = bool(
                legend.query("#legend_card_pane #legend_mac_warning_sample")
            )
            app.pop_screen()
            await pilot.pause()

            legend = await _open_legend(app, pilot, "map")
            band_rows = list(legend.query("#legend_key_pane .legend-row"))
            markup_flags = [row._render_markup for row in band_rows]
            in_key = [
                bool(legend.query(f"#legend_key_pane .{cls}"))
                for cls in ("band-constant", "band-low", "band-medium", "band-high")
            ]
            return spans, in_card, markup_flags, in_key

    spans, sample_in_card, markup_flags, bands_in_key = asyncio.run(_drive())

    # clause 1
    assert warning_style in spans, (
        f"the MAC warning sample lost its {warning_style!r} paint: {spans}"
    )
    assert sample_in_card, (
        "#legend_mac_warning_sample must stay a CARD widget after the split"
    )

    # clause 2
    assert len(markup_flags) >= 5, (
        f"expected the map band-key rows in the key pane, got {len(markup_flags)}"
    )
    assert all(flag is False for flag in markup_flags), (
        f"a band-key row lost markup=False: {markup_flags}"
    )
    assert all(bands_in_key), f"a band class left the key pane: {bands_in_key}"

    # clause 3
    expected = {site: non_empty for site, _, _, non_empty in _LEGEND_BODY_QUERY_SITES}
    for site, count in _census_legend_body_sites(tmp_path):
        assert (count > 0) is expected[site], f"{site} resolved {count} widgets"


# --------------------------------------------------------------------------- #
# AT-217 (HLR-072-6) — the floor regime, mac view, 80x24.
# --------------------------------------------------------------------------- #
def test_at217_floor_stacks_key_above_card_and_key_is_reachable(
    tmp_path: Path,
) -> None:
    """AT-217 — at 80x24 the Legend stacks the key ABOVE the card.

    1. ``#legend_key_pane.region.y < #legend_card_pane.region.y`` — key first,
       the operator's Phase-1 decision;
    2. **the non-vacuity tooth:** ``#legend_card_pane.region.height >= 2``.
       Ordering alone is TRUE in all four candidate CSS regimes measured in M-3,
       including the degenerate ``key: auto`` one that starves the card to ONE
       row and overflows the body. This clause is the only one that fails there;
    3. **reachable under scroll, NOT required visible:** the floor content budget
       is 9 rows against a 10 (mac) / 11 (map) row key, so "both fully visible"
       is physically impossible at 80x24 (C-29: relax the threshold, never ship
       an unachievable AT). Asserted as ``max_scroll_y >= 1`` plus the last key
       row landing in a non-empty on-screen region inside the pane after
       ``scroll_visible()``.
    """

    async def _drive() -> Dict[str, object]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")
            key_pane = legend.query_one("#legend_key_pane")
            card_pane = legend.query_one("#legend_card_pane")
            rows = list(legend.query("#legend_key_pane .legend-row"))
            last_row = rows[-1]
            last_row.scroll_visible(animate=False)
            await pilot.pause()
            await pilot.pause()
            return {
                "key_y": key_pane.region.y,
                "card_y": card_pane.region.y,
                "card_height": card_pane.region.height,
                "key_max_scroll_y": key_pane.max_scroll_y,
                "n_key_rows": len(rows),
                "last_row_area": last_row.region.area,
                "last_row_in_key": key_pane.region.contains_region(last_row.region),
                "key_region": key_pane.region,
                "card_region": card_pane.region,
            }

    m = asyncio.run(_drive())

    # clause 1 — key first.
    assert m["key_y"] < m["card_y"], (
        f"the key pane must stack ABOVE the card at the floor: key={m['key_region']} "
        f"card={m['card_region']}"
    )

    # clause 2 — the non-vacuity tooth.
    assert m["card_height"] >= 2, (
        "the card pane is starved (the degenerate `height: auto` key regime): "
        f"card={m['card_region']}"
    )

    # clause 3 — reachable under scroll.
    assert m["n_key_rows"] >= 1, "no key rows to reach"
    assert m["key_max_scroll_y"] >= 1, (
        "at 80x24 the key cannot fit, so it MUST be scrollable; "
        f"max_scroll_y={m['key_max_scroll_y']}"
    )
    assert m["last_row_area"] > 0 and m["last_row_in_key"], (
        "the last key row did not scroll into a non-empty region inside the key "
        f"pane: row area={m['last_row_area']}, key={m['key_region']}"
    )


# --------------------------------------------------------------------------- #
# TC-517 (LLR-072-6.1) — the regime hook itself: the class AND the document
# order flip at the breakpoint, in BOTH directions (the hook runs on every
# resize, so it must be idempotent).
# --------------------------------------------------------------------------- #
def test_tc517_width_regime_flips_class_and_pane_order(tmp_path: Path) -> None:
    """TC-517 — ``legend-narrow`` and the pane order both track the width.

    AT-217's geometry alone cannot distinguish "stacked because the regime rule
    fired" from "stacked because the panes collapsed", so the class and the
    document order are asserted directly, at the breakpoint quoted from
    ``_LEGEND_NARROW_WIDTH`` (never its literal value) and at the 80x24 floor.
    """

    async def _drive() -> List[Tuple[str, bool, List[str]]]:
        app = S19TuiApp(base_dir=tmp_path)
        seen: List[Tuple[str, bool, List[str]]] = []
        async with app.run_test(size=(_LEGEND_NARROW_WIDTH, 30)) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")

            async def _sample(label: str) -> None:
                seen.append(
                    (
                        label,
                        legend.query_one("#legend_dialog").has_class("legend-narrow"),
                        [child.id for child in legend.query_one("#legend_body").children],
                    )
                )

            await _sample("at the breakpoint")
            for width, height, label in (
                (_LEGEND_NARROW_WIDTH - 1, 30, "one column below"),
                (80, 24, "the floor"),
                (_LEGEND_NARROW_WIDTH, 30, "back to the breakpoint"),
            ):
                await pilot.resize_terminal(width, height)
                await pilot.pause()
                await pilot.pause()
                await _sample(label)
        return seen

    samples = asyncio.run(_drive())
    expected = [
        ("at the breakpoint", False, ["legend_card_pane", "legend_key_pane"]),
        ("one column below", True, ["legend_key_pane", "legend_card_pane"]),
        ("the floor", True, ["legend_key_pane", "legend_card_pane"]),
        ("back to the breakpoint", False, ["legend_card_pane", "legend_key_pane"]),
    ]
    assert samples == expected, f"width-regime hook misbehaved: {samples}"


# --------------------------------------------------------------------------- #
# TC-518 (LLR-072-6.2) — `height: auto` on the key pane is excluded BY
# MEASUREMENT (M-3): it starves the card to 1 row and overflows `#legend_body`.
# --------------------------------------------------------------------------- #
_STYLES_TCSS = Path(s19_app.__file__).resolve().parent / "tui" / "styles.tcss"


def _rule_blocks_for(selector_fragment: str) -> List[Tuple[str, str]]:
    """
    Summary:
        Split ``styles.tcss`` into ``(selector, declarations)`` blocks and return
        those whose selector mentions ``selector_fragment``.

    Args:
        selector_fragment (str): e.g. ``"#legend_key_pane"``.

    Returns:
        List[Tuple[str, str]]: matching ``(selector, body)`` pairs, comments
        stripped from the selector text.

    Data Flow:
        - Reads the stylesheet the app actually loads and splits on ``{`` / ``}``.

    Dependencies:
        Used by:
            - test_tc518_key_pane_never_uses_height_auto
    """
    text = _STYLES_TCSS.read_text(encoding="utf-8")
    blocks: List[Tuple[str, str]] = []
    for chunk in text.split("}"):
        if "{" not in chunk:
            continue
        selector, _, body = chunk.partition("{")
        selector = selector.split("*/")[-1].strip()
        if selector_fragment in selector:
            blocks.append((selector, body))
    return blocks


def test_tc518_key_pane_never_uses_height_auto(tmp_path: Path) -> None:
    """TC-518 — the key pane's height is a fraction, never ``auto``.

    Three arms, because the source and the resolved style can disagree AND the
    two regimes resolve different rules:
    (a) no ``#legend_key_pane`` rule in ``styles.tcss`` declares ``height:auto``
        — matched by REGEX, not a whitespace-exact substring. An independent
        review showed ``height:auto`` (no space) in the WIDE rule passed the old
        substring scan *and* the floor probe, because at 80x24 the narrow rule
        wins and the wide declaration is never resolved;
    (b) the LIVE resolved height at the 80x24 floor is a ``FRACTION``;
    (c) the LIVE resolved height at 120x30 is a ``FRACTION`` — the arm that
        closes the gap (a) alone left open.
    """
    blocks = _rule_blocks_for("#legend_key_pane")
    assert len(blocks) >= 2, (
        f"expected the wide + narrow key-pane rules in styles.tcss, got {blocks}"
    )
    height_auto = re.compile(r"height\s*:\s*auto", re.IGNORECASE)
    for selector, body in blocks:
        assert not height_auto.search(body), (
            f"`height: auto` on the key pane is excluded by measurement (M-3: it "
            f"starves the card to 1 row and overflows #legend_body) — {selector!r}"
        )

    async def _drive(size: Tuple[int, int]) -> Unit:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")
            return legend.query_one("#legend_key_pane").styles.height.unit

    for size in ((80, 24), (120, 30)):
        unit = asyncio.run(_drive(size))
        assert unit is Unit.FRACTION, (
            f"at {size} the key pane resolved to {unit}, not a fraction"
        )


# --------------------------------------------------------------------------- #
# TC-519 (LLR-072-7.1) — the legend DATA layer is reused, never edited.
# --------------------------------------------------------------------------- #
def _repo_root() -> Path:
    """Repo root — the ancestor of ``s19_app`` carrying ``.git`` + ``pyproject.toml``."""
    here = Path(s19_app.__file__).resolve().parent
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists() and (candidate / "pyproject.toml").exists():
            return candidate
    raise RuntimeError("could not locate the repository root from s19_app")


def test_tc519_legend_module_unchanged_vs_main() -> None:
    """TC-519 — ``git diff origin/main -- s19_app/tui/legend.py`` is empty.

    LLR-072-7.1: the two-pane split re-parents the widgets ``_render_card()`` /
    ``_render_key()`` return; it must not reconstruct rows from text, so the data
    module has no reason to change. Follows the ``test_engine_unchanged.py``
    idiom (``git diff`` is line-ending / ``__pycache__`` aware).
    """
    repo_root = _repo_root()
    ref = None
    for candidate in ("origin/main", "main"):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{candidate}^{{commit}}"],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            ref = candidate
            break
    if ref is None:
        pytest.skip("neither 'origin/main' nor 'main' is available in this checkout")

    completed = subprocess.run(
        ["git", "diff", "--name-only", ref, "--", "s19_app/tui/legend.py"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    changed = [line for line in completed.stdout.splitlines() if line.strip()]
    assert changed == [], (
        f"s19_app/tui/legend.py must be reused unmodified (vs {ref}): {changed}"
    )


# --------------------------------------------------------------------------- #
# TC-520 (Inc-4) — the focus traversal the two-pane split CHANGED.
#
# `01-requirements.md` §6.3 flagged this axis `assumed — verify in target
# framework at Phase 3`. Verified at the Inc-1/2 gate, and it moved:
# `ScrollableContainer.can_focus` is True on textual 8.2.8, so the modal went
# from ONE focusable stop to THREE, and the stops follow pane document order —
# wide `[card, key, close]`, floor `[key, card, close]`.
#
# The behaviour is ACCEPTED, not repaired, and this node pins it. The third stop
# is REQUIRED, not incidental: at the floor the key is scroll-only by design
# (AT-217 clause 3), so making the panes `can_focus = False` to restore the old
# two-stop cycle would leave the colour key unreachable by keyboard at 80x24 and
# fail guard G-4 outright.
#
# It pins the PROPERTIES, not the literal chain. A `== [card, key, close]`
# equality would break on any future container that is merely passed through, and
# would be asserting the framework's widget inventory rather than the operator-
# visible guarantee. The three properties below are the guarantee.
# --------------------------------------------------------------------------- #
def test_tc520_legend_focus_traversal_is_pinned_in_both_regimes(
    tmp_path: Path,
) -> None:
    """TC-520 — initial focus, pane reachability, and floor focus order.

    Three properties, both regimes:

    (a) **initial focus is ``#legend_close``** — the part that must NOT have
        regressed. It is what `Enter` acts on the moment the modal opens, and it
        is unchanged from the single-pane modal;
    (b) **both panes appear in ``screen.focus_chain``** — the reachability
        guarantee behind G-4. If a future change makes the panes non-focusable to
        tidy the tab cycle, the floor key becomes keyboard-unreachable and this
        arm goes RED at the cause;
    (c) **at the 80x24 floor the key pane PRECEDES the card pane in the chain** —
        the operator's key-first decision expressed in focus order, not only in
        geometry. AT-217 pins the geometric order; nothing pinned the focus
        order, and `move_child` is what produces both, so a reorder regression
        that AT-217 caught geometrically is caught here at the second surface.

    Nothing asserted a legend tab order anywhere before this node (measured at
    the Inc-1/2 gate: ``focus_chain`` / ``focused.id`` / ``press("tab")`` return
    zero hits across all four legend test files), so this is new coverage for a
    behaviour this batch caused.
    """

    async def _drive(size: Tuple[int, int]) -> Tuple[str, List[str]]:
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            legend = await _open_legend(app, pilot, "mac")
            focused = legend.focused
            return (
                "" if focused is None else str(focused.id),
                [str(widget.id) for widget in legend.focus_chain],
            )

    for size in ((120, 30), (80, 24)):
        focused_id, chain = asyncio.run(_drive(size))

        # (a) initial focus — unchanged from the single-pane modal.
        assert focused_id == "legend_close", (
            f"at {size} the Legend must open with #legend_close focused, "
            f"got {focused_id!r} (chain={chain!r})"
        )

        # (b) both panes reachable by keyboard (G-4).
        for pane in ("legend_card_pane", "legend_key_pane"):
            assert pane in chain, (
                f"at {size} #{pane} is not in the focus chain {chain!r} — the "
                "floor key is scroll-only, so a non-focusable pane makes it "
                "keyboard-unreachable"
            )

        # (c) floor order follows the key-first stacking.
        if size == (80, 24):
            assert chain.index("legend_key_pane") < chain.index(
                "legend_card_pane"
            ), (
                f"at the floor the key pane must precede the card pane in the "
                f"focus chain (key-first, the operator's decision): {chain!r}"
            )
