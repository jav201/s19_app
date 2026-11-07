"""Batch-101 Inc 12 (G-T2) - every widget of the Check Editor is shown in some
state, and the Addendum tab does what the removed hidden button mirrored.

Design under test: ``.dev-flow/2026-11-01-batch-101/inc-12/01-requirements.md``
row R-CHKED-058 (D-3, E3A-03), the cited canon row R-CHKED-021 and the
acceptance case AT-I12-3 (Check Editor half), one node per case of
``inc-12/02-test-cases.md``.

The walk drives the product's own controls (the three tab chips) and collects,
after every state, the widgets of the window ``#screen_check_editor`` (the
window itself, its header and its panel) that carry an id. The population is
the union of those widgets over the walked states, counted by widget identity,
so two widgets that share an id are two members and one shown cannot hide the
other. A widget is *shown* when ``display`` holds on it and on every widget
that holds it, up to the screen (``tests.b97_probes.is_displayed``, CTX-SHELL's
"displayed"); ``visibility`` and the region's size are not read. The walk
asserts its population size first, so a vacuous walk fails, and then that no
member is never shown. Nothing sets widget state directly and the OS clipboard
is never touched (the per-test ``LOCALAPPDATA`` isolation is the shared one).

Traceability (E4): test names start ``test_r_<row id>_...`` or ``test_at_i12_...``
so the registry binds them.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from textual.widgets import Button

from s19_app.tui.app import S19TuiApp
from tests.b97_fixtures import open_check_editor
from tests.b97_probes import is_displayed, painted_rows, settle, settled

SIZE = (118, 54)

#: (tab chip id, the pane that tab shows): the Check Editor's three tabs.
TABS = (
    ("check_tab_fields", "check_pane_fields"),
    ("check_tab_json", "check_pane_json"),
    ("check_tab_addendum", "check_pane_addendum"),
)
PANES = tuple(pane for _chip, pane in TABS)


def _drive(tmp_path: Path, body):
    """Load the demo A2L, show the Check Editor and return
    ``await body(app, pilot, panel)`` at 118x54."""

    async def _run():
        app = S19TuiApp(base_dir=tmp_path)
        async with app.run_test(size=SIZE) as pilot:
            panel = await open_check_editor(app, pilot)
            return await body(app, pilot, panel)

    return asyncio.run(_run())


class _Walk:
    """Accumulates, over the walked states, the window's widgets with an id
    (keyed by identity; the walk holds each widget, so no key is reused) and
    the keys of those shown in at least one state."""

    def __init__(self, window) -> None:
        self.window = window
        self.population: dict = {}
        self.shown: set = set()
        self.states: list = []

    def collect(self, state: str) -> None:
        for widget in (self.window, *self.window.query("*")):
            if widget.id:
                self.population[id(widget)] = widget
                if is_displayed(widget):
                    self.shown.add(id(widget))
        self.states.append(state)

    def never_shown(self) -> list:
        return sorted(w.id for key, w in self.population.items() if key not in self.shown)


def _painted(app, widget) -> str:
    return "\n".join(row.rstrip() for row in painted_rows(app, widget))


def _shown_panes(panel) -> list:
    return [pane for pane in PANES if is_displayed(panel.query_one(f"#{pane}"))]


# --------------------------------------------------------------------------- #
# R-CHKED-058 - the Check Editor walk
# --------------------------------------------------------------------------- #


def test_r_chked_058_1_every_check_editor_widget_is_shown_in_a_state(tmp_path: Path) -> None:
    """R-CHKED-058 (case /1): walk the window ``#screen_check_editor`` over
    [opened with the demo A2L; ``#check_tab_fields``, ``#check_tab_json``,
    ``#check_tab_addendum`` pressed in turn] -> 0 widgets with an id never
    shown, at least 45 in the population, and the Addendum state shows
    ``#check_addendum_preview``.

    RED on base: the hidden ``Addendum preview`` button is mounted and never
    shown in any of the four states; the failure message lists its id.
    """

    async def body(app, pilot, panel):
        walk = _Walk(app.query_one("#screen_check_editor"))
        await settled(pilot, lambda: _shown_panes(panel) == ["check_pane_fields"], "opened on the Fields tab")
        walk.collect("opened")
        addendum_state = None

        for chip_id, pane in TABS:
            panel.query_one(f"#{chip_id}", Button).press()
            await settled(
                pilot,
                lambda: _shown_panes(panel) == [pane] and panel.query_one(f"#{chip_id}").has_class("chip-selected"),
                f"the {chip_id} tab is shown alone and its chip marked",
            )
            walk.collect(chip_id)
            if chip_id == "check_tab_addendum":
                addendum_state = is_displayed(panel.query_one("#check_addendum_preview"))

        return len(walk.population), walk.never_shown(), walk.states, addendum_state

    size, never, states, addendum_state = _drive(tmp_path, body)
    assert states == ["opened", "check_tab_fields", "check_tab_json", "check_tab_addendum"], states
    assert size >= 45, (size, states)
    assert addendum_state is True, "the Addendum tab state does not show #check_addendum_preview"
    assert never == [], f"mounted and never shown: {never}"


# --------------------------------------------------------------------------- #
# AT-I12-3 (Check Editor half) - the Addendum tab by the keys
# --------------------------------------------------------------------------- #


def test_at_i12_3_addendum_tab_by_keys(tmp_path: Path) -> None:
    """AT-I12-3 (US-I12-2; R-CHKED-058 with the cited R-CHKED-021): the demo
    A2L loaded; rail key ``=`` shows the Check Editor; ``tab`` until
    ``#check_tab_addendum`` has the focus (bounded); ``enter``. The Addendum
    pane is the one shown and ``#check_addendum_preview`` paints the addendum
    text starting ``## Checks``.

    Holds on base (R): the Addendum tab chip already carries the function; the
    walk node carries the removed button.
    """

    async def body(app, pilot, panel):
        await pilot.press("1")
        await settled(pilot, lambda: not is_displayed(panel), "the Check Editor is left for the Workspace")
        await pilot.press("=")
        await settled(pilot, lambda: is_displayed(panel), "rail key = shows the Check Editor")
        chip = panel.query_one("#check_tab_addendum", Button)
        before = _shown_panes(panel)

        focused = False
        for _ in range(150):
            if app.focused is chip:
                focused = True
                break
            await pilot.press("tab")
            await settle(pilot, 1)
        assert focused, f"tab did not reach #check_tab_addendum in 150 presses; focus is {app.focused!r}"

        await pilot.press("enter")
        await settled(
            pilot,
            lambda: _shown_panes(panel) == ["check_pane_addendum"],
            "enter on the Addendum chip shows the Addendum pane alone",
        )
        preview = panel.query_one("#check_addendum_preview")
        await settled(pilot, lambda: _painted(app, preview).startswith("## Checks"), "the addendum text is painted")
        return before, is_displayed(preview), _painted(app, preview), chip.has_class("chip-selected")

    before, preview_shown, text, marked = _drive(tmp_path, body)
    assert before == ["check_pane_fields"], before
    assert preview_shown is True
    assert text.startswith("## Checks"), text[:80]
    assert marked is True
