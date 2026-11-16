"""Inc 7 E4 mutant run (MU7): nodes that kill the mutants the shipped nodes let survive.

Each test names the mutant it separates (``.dev-flow/2026-11-05-batch-103/inc-7/E4-mutants.md``).
The fixtures and helpers are the ones of ``test_b103_label_list.py``.
"""
from __future__ import annotations

from unittest import mock

from tests.support.b103_label_list import build_case08, run_a2l, settle, static_text  # noqa: F401
from tests.test_b103_label_list import (  # noqa: F401
    case08,
    enriched,
    expect,
    names,
    run_modal,
    said,
    type_text,
    ll,
)


def test_the_similar_line_holds_exactly_three_closest_names(ll, names, enriched, monkeypatch) -> None:
    """MU32 (CLOSEST_LIMIT 3 -> 4): R-A2L-LIST.049/1 compared with ``in``, so a fourth name passed.

    The line of ``VALUE_002`` ends with its third closest name; the fourth ranked name is a
    different one, so a fourth name on the line is a failure.
    """
    first_three = [m.name for m in expect(names, "VALUE_002", 3)]
    fourth = [m.name for m in expect(names, "VALUE_002", 4)][3]
    assert fourth not in first_three

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "VALUE_0002\nCURVE_0001\nVALUE_002\n")
        return said(modal, "a2l_list_similar")

    text = run_modal(monkeypatch, enriched, names, sc)[1]
    line = next(x for x in text.splitlines() if x.startswith("  similar to #3 VALUE_002: "))
    assert line == "  similar to #3 VALUE_002: " + " · ".join(first_three)


def test_the_paste_window_paints_nothing_once_the_app_has_stopped(ll, names, enriched, monkeypatch) -> None:
    """MU05c (``is_running`` dropped from ``_preview``'s guard): R-A2L-LIST.086, window still attached.

    The window is attached but the app reports it is not running: a preview that comes due
    then paints nothing, so the counts line keeps the text it had.
    """

    async def sc(app, pilot, modal, seen):
        await type_text(pilot, modal, "VALUE_0002\nCURVE_0001")
        before = said(modal, "a2l_list_counts")
        assert before.startswith("2 pasted")
        modal.query_one("#a2l_list_text").text = "VALUE_0002\nCURVE_0001\nMAP_0003"
        with mock.patch.object(type(app), "is_running", new_callable=mock.PropertyMock, return_value=False):
            modal._preview()
            after = said(modal, "a2l_list_counts")
        return before, after

    before, after = run_modal(monkeypatch, enriched, names, sc)[1]
    assert after == before


def _body_state(app) -> tuple:
    body = app.query_one("#a2l_panes")
    return body.size.width, body.size.height, "-wide" in body.classes, "-short" in body.classes


def test_the_body_regime_changes_exactly_at_its_thresholds(case08, tmp_path) -> None:
    """MU22a/b/c (WIDE_AT 180, STACK_MIN_HEIGHT 32, STACK_MIN_WIDTH 110): R-A2L-LIST.080-.083, R-TUI-037.

    The regime follows the measured body: ``-wide`` exactly from 180 columns, ``-short`` exactly
    when it is not wide and is under 110 columns or under 32 rows. The sweep is checked to
    reach both sides of each threshold, so a missed boundary fails the test instead of passing it.
    """

    async def sc(app, pilot):
        states = []
        for width, height in (
            [(w, 54) for w in range(126, 140)]
            + [(w, 54) for w in range(196, 212)]
            + [(150, h) for h in range(40, 56)]
        ):
            await pilot.resize_terminal(width, height)
            await settle(pilot, 4)
            states.append(_body_state(app))
        return states

    states = run_a2l(tmp_path, case08, sc, size=(118, 54))
    for body_w, body_h, wide, short in states:
        assert wide == (body_w >= 180), (body_w, body_h)
        assert short == (not wide and (body_w < 110 or body_h < 32)), (body_w, body_h)
    widths = {s[0] for s in states}
    heights = {s[1] for s in states if s[0] >= 110}
    assert {179, 180} <= widths and {109, 110} <= widths, sorted(widths)
    assert {31, 32} <= heights, sorted(heights)
